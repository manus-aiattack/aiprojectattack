
import json
import re
from core.logger import log


class CredentialHarvesterAgent:
    def __init__(self, context_manager):
        self.context_manager = context_manager
        self.db_manager = context_manager.orchestrator.db_manager

    async def run(self):
        log.info("Running Credential Harvester Agent...")
        target_host = self.context_manager.target_host

        # Get all findings from Redis
        all_findings = self.db_manager.get_all_findings_for_host(target_host)

        usernames = set()
        passwords = set()

        # Regex for emails and potential usernames in paths
        email_regex = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2}'
        path_username_regex = r'/(users|home)/([a-zA-Z0-9_.-]+)'

        for finding in all_findings:
            try:
                # Search for usernames and passwords in the finding content
                content = str(finding)

                # Emails
                found_emails = re.findall(email_regex, content)
                for email in found_emails:
                    usernames.add(email.split('@')[0])

                # Usernames from paths
                found_path_usernames = re.findall(path_username_regex, content)
                for match in found_path_usernames:
                    usernames.add(match[1])

                # A simple password regex (this should be improved)
                password_regex = r'password[\'"\s]*:[\'"\s]*([a-zA-Z0-9_!@#$%^&*]+)'
                found_passwords = re.findall(
                    password_regex, content, re.IGNORECASE)
                for password in found_passwords:
                    passwords.add(password)

            except Exception as e:
                log.warning(f"Could not parse finding: {e}")

        if usernames:
            log.success(f"Harvested {len(usernames)} potential usernames.")
            await self.db_manager.redis.sadd(f"credentials:{target_host}:usernames", *list(usernames))

        if passwords:
            log.success(f"Harvested {len(passwords)} potential passwords.")
            await self.db_manager.redis.sadd(f"credentials:{target_host}:passwords", *list(passwords))

        log.info("Credential Harvester Agent finished.")
