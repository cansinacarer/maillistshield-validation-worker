from .knowledge_base import *

import dns.resolver
import tldextract
import socket
import re
import subprocess
import datetime
from dateutil import parser


# Everything reported about an email
class Email:
    def __init__(self, email, catch_all_test=False):
        self.email = email

        # Is this instance used with a bogus email for catch all testing?
        self.is_catch_all_test = catch_all_test

        # Is the input in valid email format?
        self.is_valid_syntax = False

        # Everything before @ sign
        self.account = ""

        # Is role (Does this account belong to a role like accounting@example.com)
        self.is_role = False

        # Is alias (i.e. does account have a + sign)?
        self.is_alias = False

        # Everything before + sign, if + exists, account otherwise
        self.account_alias_stripped = ""

        # Email with the alias stripped, if alias exists, email otherwise
        self.email_alias_stripped = ""

        # FQDN after the @ sign
        self.fqdn = ""

        # Parsed sections of the FQDN
        self.subdomain, self.domain, self.tld = "", "", ""

        # Age of the domain
        self.domain_age = -1

        # First MX record
        (
            self.smtp_provider_host,
            self.smtp_provider_host_domain,
            self.smtp_provider_host_tld,
        ) = ("", "", "")

        # IP resolved from the hostname of the first MX record
        self.smtp_provider_ip = ""

        # PTR record for the IP of the hostname of the first MX record
        self.smtp_provider_ip_ptr = ""

        # Does the domain have MX records?
        self.has_mx_records = False

        # Is the email served by a disposable email provider
        # Based on checking mx host and ip against my blacklist
        # IP blacklist: IPs of above and inboxes.com mailserver
        self.is_disposable = False

        # Is the email served by a free provider like gmail, yahoo, etc.
        # Based on checking the email domain against known free providers
        self.is_free_provider = False

        # Autodiscover cname value
        self.autodiscover_host, self.autodiscover_domain, self.autodiscover_host_tld = (
            "",
            "",
            "",
        )

        # Email security gateway
        self.email_security_gateway = ""

        # Email provider
        self.email_provider = ""

        # SMTP responses parsed
        self.smtp_response = []

        # Catch-all (all accounts exist)
        self.is_catch_all = False

        # Is mailbox full?
        # Will soft bounce
        self.is_mailbox_full = False

        # The phrases we found in the SMTP responses during verification
        self.phrase_matches = []

        # Verdict: Is the email valid?
        self.status = ""
        self.status_detail = ""

    # Main method of this class
    def validate(self):

        # If the syntax isn't valid, no need to do the rest
        self.check_syntax()
        if not self.is_valid_syntax:
            return self.quit_without_further_validations(
                "invalid", "email address did not pass the syntax check"
            )

        self.parse_account()
        self.check_if_alias()
        self.parse_domain()
        self.get_domain_age()
        self.parse_account_alias_stripped()
        self.check_if_free_provider()

        # If the email domain doesn't have a name server, no need to do the rest
        if not self.has_name_servers():
            return self.quit_without_further_validations(
                "invalid", "email domain does not have name servers"
            )

        self.parse_autodiscover()
        self.parse_mx_record()

        # If the email domain doesn't have an mx record, no need to do the rest
        if not self.has_mx_records:
            return self.quit_without_further_validations(
                "invalid", "email domain does not have emails set up"
            )

        # Check the mx record against known disposable email providers
        self.check_if_disposable()

        # Check if the mx record uses a proxy like proofpoint, mimecast, barracuda, cisco ironport
        self.check_for_security_gateway()

        # Get the email provider based on the mx record
        self.find_email_provider()

        # Connect to the mail server to validate the account
        try:
            self.evaluate_smtp_connection()
        except Exception as a:
            self.status = "unknown"
            self.status_detail = "we encountered an error while trying to connect with the email provider"

        # Return the results after all checks are done
        # This is overwritten by quit_without_further_validations if the email is found to be invalid before all checks are completed
        return self.results()

    # Returns a dict with the current values of the results
    def results(self):
        return vars(self)

    # Quit verification without further validations
    def quit_without_further_validations(self, status, status_detail):
        # Update the status
        self.status = status
        self.status_detail = status_detail

        # Return what we have without further validations
        return self.results()

    def check_syntax(self):
        # Define the regex pattern for a valid email
        pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"

        # Check the email against the pattern
        if re.match(pattern, self.email):
            self.is_valid_syntax = True

    def parse_account(self):
        self.account = self.email.split("@")[0]
        self.is_role = self.account in role_email_accounts

    def check_if_alias(self):
        self.is_alias = "+" in self.account

    def parse_domain(self):
        self.fqdn = self.email.split("@")[1]

        extract = tldextract.extract(self.fqdn)
        self.subdomain, self.domain, self.tld = (
            extract.subdomain,
            extract.domain,
            extract.suffix,
        )

    def get_domain_age(self):
        domain = f"{self.domain}.{self.tld}"

        try:
            # Run whois command and capture output
            whois_output = subprocess.check_output(["whois", domain], timeout=2).decode(
                "utf-8"
            )

            # Look for creation date in whois output
            for line in whois_output.splitlines():
                if "Creation Date:" in line:
                    creation_date_str = line.split("Creation Date:")[1].strip()
                    creation_date = parser.parse(creation_date_str)

                    # Calculate domain age
                    current_date = datetime.datetime.now(datetime.timezone.utc)
                    domain_age = current_date - creation_date

                    self.domain_age = domain_age.days

        except Exception as e:
            pass

    def parse_account_alias_stripped(self):
        self.account_alias_stripped = self.account.split("+")[0]
        self.email_alias_stripped = self.account_alias_stripped + "@" + self.fqdn

    def check_if_free_provider(self):
        # Is fqdn in the free providers list?
        self.is_free_provider = self.fqdn in free_email_domains

    # Does the domain have name servers?
    def has_name_servers(self):
        try:
            answers = dns.resolver.resolve(f"{self.domain}.{self.tld}", "NS")
            nameservers = [str(rdata) for rdata in answers]
            return True
        # TODO: More detailed reporting by error type
        except dns.resolver.NoNameservers:
            return False
        except dns.resolver.NXDOMAIN:
            return False
        except:
            return False

    # Get autodiscover cname record
    def parse_autodiscover(self):
        try:
            answers = dns.resolver.resolve(f"autodiscover.{self.fqdn}", "CNAME")
            self.autodiscover_host = answers[0].target.to_text()
            extract = tldextract.extract(self.autodiscover_host)
            self.autodiscover_domain, self.autodiscover_host_tld = (
                extract.domain,
                extract.suffix,
            )
        except:
            return ""

    # Find the IP address from the hostname
    @staticmethod
    def get_ip_address(hostname):
        try:
            ip_address = socket.gethostbyname(hostname)
            return ip_address
        except:
            return None

    @staticmethod
    # Find the hostname from the IP address
    def get_ptr_record(ip_address):
        try:
            ptr_record = socket.gethostbyaddr(ip_address)
            return ptr_record[0]
        except:
            return ""

    # Get mx records
    def parse_mx_record(self):
        try:
            self.smtp_provider_host = dns.resolver.resolve(self.fqdn, "MX")[
                0
            ].exchange.to_text()[:-1]
            extract = tldextract.extract(self.smtp_provider_host)
            self.smtp_provider_host_domain, self.smtp_provider_host_tld = (
                extract.domain,
                extract.suffix,
            )
            self.smtp_provider_ip = Email.get_ip_address(self.smtp_provider_host)
            self.smtp_provider_ip_ptr = Email.get_ptr_record(self.smtp_provider_ip)
            self.has_mx_records = True
        except:
            # We pass here because self.validate() will quit if has_mx_records is False
            pass

    def check_if_disposable(self):
        if self.smtp_provider_ip in disposable_smtp_provider_ips:
            self.is_disposable = True

    def check_for_security_gateway(self):
        self.email_security_gateway = email_security_gateway_map.get(
            self.smtp_provider_host_domain, ""
        )

    def find_email_provider(self):
        # If there is an email security gateway, try to use autodiscover to get the email provider
        if self.email_security_gateway != "":

            # Try to get email provider from autodiscover, if we recognize the domain
            provider_from_autodiscover = (
                email_provider_names_by_autodiscover_domain.get(
                    self.autodiscover_domain, ""
                )
            )

            # If we found a known provider from autodiscover, use it and exit
            if provider_from_autodiscover != "":
                self.email_provider = provider_from_autodiscover
                return

        # If there is no email security gateway, use the second level domain of the smtp provider (smtp_provider_host_domain)
        # If we recognize the domain, use the friendly name,
        # otherwise use the domain itself without the tld
        self.email_provider = email_provider_names_by_smtp_provider_host_domain.get(
            self.smtp_provider_host_domain, self.smtp_provider_host_domain
        )

    # Parse the SMTP response
    @staticmethod
    def parse_smtp_response(response):
        # Parse the code
        code = response[:3]

        # Check if subcode exists
        subcode_exists = (
            response[4:5].isdigit()
            and response[6:7].isdigit()
            and response[8:9].isdigit()
        )

        # Parse the subcode
        subcode = response[4:9] if subcode_exists else ""

        # Strip new lines, code-subcode and code-subcode patterns from message
        message = (
            response.replace(f"{code}", "")
            .replace(f"{code}-", "")
            .replace(f"{subcode}", "")
            .replace("\r\n", " ")
            .strip()
        )

        result = {"code": code, "subcode": subcode, "message": message}
        return result

    # We made this a static method because I
    def make_bogus_smtp_connection(self):
        # Define the server address and port
        server_address = (self.smtp_provider_host, 25)

        # Create a TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Parsed responses
        response = []

        try:
            # Connect to the server
            sock.connect(server_address)

            # Send the HELO command
            helo_command = "HELO fancydomain.com\r\n"
            sock.sendall(helo_command.encode())

            # Receive and print the server response
            parsed_response = Email.parse_smtp_response(sock.recv(1024).decode())
            response.append(parsed_response)

            # Send the MAIL FROM command
            mail_from_command = "MAIL FROM: <test@fancydomain.com>\r\n"
            sock.sendall(mail_from_command.encode())

            # Receive and print the server response
            parsed_response = Email.parse_smtp_response(sock.recv(1024).decode())
            response.append(parsed_response)

            # Send the RCPT TO command
            rcpt_to_command = f"RCPT TO: <{self.email}>\r\n"
            sock.sendall(rcpt_to_command.encode())

            # Receive and print the server response
            parsed_response = Email.parse_smtp_response(sock.recv(1024).decode())
            response.append(parsed_response)

            # Send the QUIT command
            quit_command = "QUIT\r\n"
            sock.sendall(quit_command.encode())

            # Receive and print the server response
            parsed_response = Email.parse_smtp_response(sock.recv(1024).decode())
            response.append(parsed_response)

        finally:
            # Close the socket
            sock.close()

            return response

    # We use this function to remove the email address being tested from the messages
    # so that phrases in the email address which is mentioned in SMTP response messages
    # doesn't match our validation phrases
    @staticmethod
    def strip_email_being_tested(message):
        return re.sub(r"<[^>]*>", "", message)

    # Check if self.smtp_response contain a phrase from our lists
    def response_matched_phrases_in_list(self, phrase_list):
        # TODO: We can simplify this learning which message to check and only checking that message
        matched = False
        # Loop all messages in the response
        for response in self.smtp_response:
            # Loop all messages in list
            for phrase in phrase_list:
                if phrase.lower() in Email.strip_email_being_tested(
                    response["message"].lower()
                ):
                    matched = True
                    self.phrase_matches.append((phrase, response["message"]))

        return matched

    def evaluate_smtp_connection(self):
        # Obtain the SMTP responses
        self.smtp_response = self.make_bogus_smtp_connection()

        # If this is the bogus email we are testing
        # we already obtained the smtp response codes, we can exit
        if self.is_catch_all_test:
            return None

        # If this is not our bogus email address we are testing
        else:
            # If the mail server returns 250 or 251 in the 4th response
            # we know that the email is deliverable but we don't know
            # whether this is because the domain has a catch all address
            if (
                self.smtp_response[3]["code"] == "250"
                or self.smtp_response[3]["code"] == "251"
            ):

                # Either way, sending to this address will work since it returned 250
                self.status = "valid"
                self.status_detail = (
                    "email provider confirmed that the email address is deliverable"
                )

                # To test if it responds 250 for all addresses, we make up an address
                bogus_email_for_catch_all_testing = (
                    "34cq0f89unymc43fn0um" + "@" + self.fqdn
                )

                # Then try to validate that
                # TODO: We can save execution time by not running all then verifications for it
                instance_for_catch_all_testing = Email(
                    bogus_email_for_catch_all_testing, True
                )
                bogus_address_result = instance_for_catch_all_testing.validate()

                # If the mail server returns 250 or 251 for our bogus email address as well,
                # we know that is has a catch all inbox
                if (
                    bogus_address_result["smtp_response"][3]["code"] == "250"
                    or bogus_address_result["smtp_response"][3]["code"] == "251"
                ):
                    self.is_catch_all = True

            # Check if this is a disabled address
            if self.response_matched_phrases_in_list(account_disabled_messages):
                self.status = "disabled"
                self.status_detail = (
                    "email provider confirmed that the email address is disabled"
                )

            # Check if this is a full mailbox case
            if self.response_matched_phrases_in_list(mailbox_full_messages):
                self.status = "valid"
                self.status_detail = "email address exists but mailbox is full"
                self.is_mailbox_full = True

            # Check if this is an invalid email address case
            if self.response_matched_phrases_in_list(invalid_email_messages):
                self.status = "invalid"
                self.status_detail = (
                    "email provider confirmed that email address does not exist"
                )

            # Check if this is a case where we are blacklisted
            if self.response_matched_phrases_in_list(blacklist_messages):
                self.status = "unknown"
                self.status_detail = "email provider does not allow us to validate"

            # If nothing above set a status
            if self.status == "":
                # 5yz_Permanent_negative_completion
                # https://en.wikipedia.org/wiki/List_of_SMTP_server_return_codes#%E2%80%94_5yz_Permanent_negative_completion
                if (
                    self.smtp_response[3]["code"][0] == "4"
                    or self.smtp_response[3]["code"][0] == "5"
                ):
                    self.status = "likely_invalid"
                    self.status_detail = "email provider rejects our connection requests, but we are not blacklisted, which likely means email deliveries will fail"

            # If nothing above set a status
            if self.status == "":
                self.status = "unknown"
                self.status_detail = "we were not able to identify the status"
