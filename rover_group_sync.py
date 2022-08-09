#!/usr/bin/env python3

import argparse
import github
import ldap3
import logging
import os
import pathlib
import re
import requests
import ssl
import yaml

logging.basicConfig(
    format='%(asctime)s %(message)s',
    datefmt='%FT%T%Z',
)

github_login_re = re.compile(r'^Github->https://github.com/([^/?]+)$')
quay_user_re = re.compile(r'^Quay->https://quay.io/user/([^/?]+)$')
user_name_re = re.compile(r'uid=([^,]+),.*')

class RoverGroupSync:
    def __init__(self, config):
        self.config = config
        self.ldap_user_cache = {}
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

    def get_github_login(self, user_name):
        ldap_user = self.get_ldap_user(user_name)
        if not ldap_user:
            return None

        for social_url in ldap_user.rhatSocialUrl:
            re_match = github_login_re.match(social_url)
            if re_match:
                return re_match.group(1)

        logging.warning(f"Unable to find GitHub social url for {user_name} in Rover LDAP")
        return None

    def get_github_logins_for_rover_group(self, rover_group_name):
        '''
        Lookup group members in Rover LDAP and return the GitHub login for each
        user from their social URL for GitHub.
        '''
        github_logins = []

        for user_name in self.get_ldap_group_members(rover_group_name):
            github_login = self.get_github_login(user_name)
            if github_login:
                github_logins.append(github_login)

        return github_logins

    def get_quay_user(self, user_name):
        ldap_user = self.get_ldap_user(user_name)
        if not ldap_user:
            return None

        for social_url in ldap_user.rhatSocialUrl:
            re_match = quay_user_re.match(social_url)
            if re_match:
                return re_match.group(1)

        logging.warning(f"Unable to find Quay social url for {user_name} in Rover LDAP")
        return None

    def get_quay_users_for_rover_group(self, rover_group_name):
        '''
        Lookup group members in Rover LDAP and return the Quay user for each
        user from their social URL for Quay.
        '''
        quay_users = []

        for user_name in self.get_ldap_group_members(rover_group_name):
            quay_user = self.get_quay_user(user_name)
            if quay_user:
                quay_users.append(quay_user)

        return quay_users

    def get_github_user(self, github_login):
        github_user = self.github_user_cache.get(github_login)
        if github_user:
            return github_user

        github_user = self.github_session.get_user(github_login)
        self.github_user_cache[github_login] = github_user
        return github_user

    def get_ldap_group_members(self, rover_group_name):
        group_reader = ldap3.Reader(
            self.ldap_connection, self.ldap_group_object_def, self.ldap_group_base_dn,
            f"cn:={rover_group_name}"
        )
        group_reader.search()

        for group in group_reader:
            member_names = []
            for user_dn in group['uniqueMember']:
                user_name = user_name_re.sub(r'\1', user_dn)
                member_names.append(user_name)
            return member_names

        logger.warning(f"Unable to find group {rover_group_name} in LDAP")
        return []

    def get_ldap_user(self, user_name):
        ldap_user = self.ldap_user_cache.get(user_name)
        if ldap_user:
            return ldap_user
        user_reader = ldap3.Reader(
            self.ldap_connection, self.ldap_user_object_def, self.ldap_user_base_dn,
            "uid:=" + user_name
        )
        for ldap_user in user_reader.search():
            self.ldap_user_cache[user_name] = ldap_user
            return ldap_user
        else:
            logging.warning(f"Unable to find user {user_name} in Rover LDAP")
            return None

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

    def sync_group_access(self):
        self.ldap_init()

        #github_config = self.config.get('github')
        #if github_config:
        #    self.github_init()
        #    for github_org_config in github_config.get('organizations', []):
        #        self.sync_github_org(github_org_config)

        quay_config = self.config.get('quay')
        if quay_config:
            for quay_org_config in quay_config.get('organizations', []):
                self.sync_quay_org(quay_org_config)


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
                    rover_group_name = github_team_config['name'],
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
                print(f"Removing {github_login} from org {github_org.login}")
                try:
                    github_user = self.get_github_user(github_login)
                    github_org.remove_from_members(github_user)
                except:
                    logging.exception(f"Unable to remove user {github_login} from {github_org.login} admins")

        for github_login in github_logins:
            try:
                print(f"Adding {github_login} as admin of {github_org.login}")
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
                print(f"Removing {github_login} from team {github_team.name} in org {github_org.login}")
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

    def sync_quay_org(self, quay_org_config):
        quay_org_name = quay_org_config['name']
        quay_org_token = quay_org_config['token']
        for quay_team_config in quay_org_config.get('teams', []):
            self.sync_quay_team(
                quay_org_name = quay_org_name,
                quay_team_name = quay_team_config['name'],
                quay_token = quay_org_token,
                rover_group_name = quay_team_config['group'],
            )

    def sync_quay_team(self, quay_org_name, quay_team_name, quay_token, rover_group_name):
        quay_users = self.get_quay_users_for_rover_group(rover_group_name)
        print(quay_users)

        resp = requests.get(
            f"https://quay.io/api/v1/organization/{quay_org_name}/team/{quay_team_name}/members",
            headers = {"Authorization": f"Bearer {quay_token}"},
        )

        for quay_team_member in resp.json()['members']:
            quay_user_name = quay_team_member['name']
            if quay_user_name in quay_users:
                # User is already a member of team, drop from list to handle
                quay_users.remove(quay_user_name)
            else:
                print(f"Removing {quay_user_name} from Quay team {quay_team_name} in org {quay_org_name}")
                try:
                    resp = requests.delete(
                        f"https://quay.io/api/v1/organization/{quay_org_name}/team/{quay_team_name}/members/{quay_user_name}",
                        headers = {"Authorization": f"Bearer {quay_token}"},
                    )
                    resp.raise_for_status()
                except:
                    logging.exception(f"Unable to remove user {quay_user_name} from Quay team {quay_team_name} in org {quay_org_name}")

        for quay_user_name in quay_users:
            print(f"Adding {quay_user_name} to team {quay_team_name} in {quay_org_name}")
            try:
                resp = requests.put(
                    f"https://quay.io/api/v1/organization/{quay_org_name}/team/{quay_team_name}/members/{quay_user_name}",
                    headers = {"Authorization": f"Bearer {quay_token}"},
                )
                resp.raise_for_status()
            except:
                logging.exception(f"Unable to add user {quay_user_name} to team {quay_team_name} in {quay_org_name}")


def main():
    argparser = argparse.ArgumentParser(description='Synrchronize GitHub teams to Rover groups')
    argparser.add_argument('--config', metavar="FILE", type=pathlib.Path, required=True)
    args = argparser.parse_args()
    with args.config.open() as f:
        config = yaml.safe_load(f)
        rover_group_sync = RoverGroupSync(config=config)
        rover_group_sync.sync_group_access()


if __name__ == '__main__':
    main()
