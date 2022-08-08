#!/usr/bin/env python3

import argparse
import github
import ldap3
import logging
import os
import pathlib
import re
import ssl
import yaml


logging.basicConfig(
    format='%(asctime)s %(message)s',
    datefmt='%FT%T%Z',
)

github_login_re = re.compile(r'Github->https://github.com/(.*)')
user_name_re = re.compile(r'uid=([^,]+),.*')

class RoverGroupGithubTeamSync:
    def __init__(self, config):
        self.config = config
        self.github_login_cache = {}
        self.github_user_cache = {}

    @property
    def github_token(self):
        return self.config.get('github', {}).get('token', os.environ.get('GITHUB_TOKEN'))

    @property
    def ldap_group_base_dn(self):
        return self.config.get('rover_ldap', {}).get('group_base_dn', 'ou=managedGroups,dc=redhat,dc=com')

    @property
    def ldap_user_base_dn(self):
        return self.config.get('rover_ldap', {}).get('user_base_dn', 'ou=users,dc=redhat,dc=com')

    def get_github_logins_for_rover_group(self, rover_group_name):
        '''
        Lookup group members in Rover LDAP and return the GitHub login for each
        user from their social URL for GitHub.
        '''
        github_logins = []

        group_reader = ldap3.Reader(
            self.ldap_connection, self.ldap_group_object_def, self.ldap_group_base_dn,
            f"cn:={rover_group_name}"
        )
        group_reader.search()

        for group in group_reader:
            for user_dn in group['uniqueMember']:
                user_name = user_name_re.sub(r'\1', user_dn)
                github_login = self.get_github_login(user_name)
                if github_login:
                    github_logins.append(github_login)

        return github_logins

    def get_github_login(self, user_name):
        github_login = self.github_login_cache.get(user_name)
        if github_login:
            return github_login
        user_reader = ldap3.Reader(
            self.ldap_connection, self.ldap_user_object_def, self.ldap_user_base_dn,
            "uid:=" + user_name
        )
        for user in user_reader.search():
            for social_url in user.rhatSocialUrl:
                re_match = github_login_re.match(social_url)
                if re_match:
                    github_login = re_match.group(1)
                    self.github_login_cache[user_name] = github_login
                    return github_login
            else:
                logging.warning(f"Unable to find GitHub social url for {user_name} in Rover LDAP")
                return None
        else:
            logging.warning(f"Unable to find user {user_name} in Rover LDAP")
            return None

    def get_github_user(self, github_login):
        github_user = self.github_user_cache.get(github_login)
        if github_user:
            return github_user

        github_user = self.github_session.get_user(github_login)
        self.github_user_cache[github_login] = github_user
        return github_user

    def github_init(self):
        self.github_session = github.Github(self.github_token)
        self.github_session_login = self.github_session.get_user().login

    def ldap_init(self):
        ldap_config = self.config.get('rover_ldap', {})
        ldap_url = ldap_config.get('url', os.environ.get('ROVER_LDAP_URL', 'ldaps://ext-ldap.corp.redhat.com'))
        bind_dn = ldap_config.get('bind_dn', os.environ.get('ROVER_LDAP_BIND_DN'))
        bind_password = ldap_config.get('bind_password', os.environ.get('ROVER_LDAP_BIND_PASSWORD'))
    
        server = ldap3.Server(
            ldap_url,
            tls = ldap3.Tls(
                ca_certs_file = None,
                validate = ssl.CERT_REQUIRED,
                version = ssl.PROTOCOL_TLSv1,
            ),
            use_ssl = True,
        )
        
        self.ldap_connection = ldap3.Connection(ldap_url, bind_dn, bind_password)
        self.ldap_connection.bind()

        self.ldap_group_object_def = ldap3.ObjectDef('groupOfUniqueNames', self.ldap_connection)
        self.ldap_user_object_def = ldap3.ObjectDef('inetOrgPerson', self.ldap_connection)
        self.ldap_user_object_def += 'rhatSocialUrl'

    def sync_github(self):
        self.github_init()
        self.ldap_init()
        for github_org_config in self.config.get('github', {}).get('organizations', []):
            self.sync_github_org(github_org_config)

    def sync_github_org(self, github_org_config):
        github_org = self.github_session.get_organization(github_org_config['name'])
        admin_group = github_org_config.get('admin_group')

        if admin_group:
            self.sync_github_org_admins(
                github_org = github_org,
                rover_group_name = admin_group,
            )

        if 'teams' in github_org_config:
            github_teams_by_name = {}
            for github_team in github_org.get_teams():
                github_teams_by_name[github_team.name] = github_team

            for github_team_config in github_org_config.get('teams'):
                github_team_name = github_team_config['name']
                github_team = github_teams_by_name[github_team_name]
                if not github_team:
                    github_team = github_org.create_team(github_team_name)

                self.sync_github_team(
                    github_org = github_org,
                    github_team = github_team,
                    rover_group_name = github_team_config.get('group', github_team_config['name']),
                )

    def sync_github_org_admins(self, github_org, rover_group_name):
        github_logins = self.get_github_logins_for_rover_group(rover_group_name)

        # Remove access for users not in group
        for github_org_member in github_org.get_members(role="admin"):
            github_login = github_org_member.login

            if github_login == self.github_session_login:
                # Do not remove access for authenticated user!
                pass
            elif github_login in github_logins:
                # Login already has admin access, drop from list to handle
                github_logins.remove(github_login)
            else:
                print(f"Removing {user_name} from org {github_org.login}")
                try:
                    github_user = self.get_github_user(github_login)
                    github_org.remove_from_members(github_user)
                except:
                    logging.exception(f"Unable to remove user {github_login} from {github_org.login} admins")

        for github_login in github_logins:
            try:
                print(f"Adding {user_name} as admin of {github_org.login}")
                github_user = self.github_session.get_user(github_login)
                github_org.add_to_members(github_user, "admin")
            except:
                logging.exception(f"Unable to add user {github_login} to {github_org.login} admins")

    def sync_github_team(self, github_org, github_team, rover_group_name):
        github_logins = self.get_github_logins_for_rover_group(rover_group_name)

        # Remove membership for users not in group
        for github_team_member in github_team.get_members():
            github_login = github_team_member.login
            if github_login in github_logins:
                # Login is already a member, drop from list to handle
                github_logins.remove(github_login)
            else:
                print(f"Removing {user_name} from team {github_team.name} in org {github_org.login}")
                try:
                    github_user = self.get_github_user(github_login)
                    github_team.remove_membership(github_user)
                except:
                    logging.exception(f"Unable to remove user {github_login} from team {github_team.name} in org {github_org.login}")

        for github_login in github_logins:
            print(f"Adding user {github_login} to GitHub team {github_team.name} in org {github_org.login}")
            try:
                github_user = self.get_github_user(github_login)
                github_team.add_membership(github_user)
            except:
                logging.exception(f"Unable to add user {github_login} to team {github_team.name} in org {github_org.login}")


def main():
    argparser = argparse.ArgumentParser(description='Synrchronize GitHub teams to Rover groups')
    argparser.add_argument('--config', metavar="FILE", type=pathlib.Path, required=True)
    args = argparser.parse_args()
    with args.config.open() as f:
        config = yaml.safe_load(f)
        rover_group_github_team_sync = RoverGroupGithubTeamSync(config=config)
        rover_group_github_team_sync.sync_github()


if __name__ == '__main__':
    main()
