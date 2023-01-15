"""Password Validator"""
from abc import ABC, abstractmethod
from string import digits, punctuation, ascii_uppercase, ascii_lowercase
from hashlib import sha1
from requests import get


class WeakPassword(Exception):
    """Weak password exception"""


class StrongPassword(Exception):
    """Strong password exception"""


class Validator(ABC):
    """Interface"""
    @abstractmethod
    def __init__(self):
        pass

    @abstractmethod
    def is_valid(self):
        """valid interface"""


class HasNumberValidator(Validator):
    """Check number in password (str) """
    def __init__(self, password):
        self.password = password

    def is_valid(self):
        if any([True for char in self.password if char in digits]):
            return True
        raise WeakPassword('Password dont have number')


class HasSpecialCharactersValidator(Validator):
    """Check special characters in password (str) """
    def __init__(self, password):
        self.password = password

    def is_valid(self):
        if any([True for char in self.password if char in punctuation]):
            return True
        raise WeakPassword('Password dont have special character')


class HasUpperCharactersValidator(Validator):
    """Check upper case in password (str) """
    def __init__(self, password):
        self.password = password

    def is_valid(self):
        if any([True for char in self.password if char in ascii_uppercase]):
            return True
        raise WeakPassword('Password dont have upper character')


class HasLowerCharacterValidator(Validator):
    """Check lower case in password (str) """
    def __init__(self, password):
        self.password = password

    def is_valid(self):
        if any([True for char in self.password if char in ascii_lowercase]):
            return True
        raise WeakPassword('Password dont have lower character')


class LengthValidator(Validator):
    """Check password length: password (str) min length is 8 char"""
    def __init__(self, password):
        self.password = password

    def is_valid(self):
        if len(self.password) < 8:
            raise WeakPassword('Too short password')
        return True


class HaveIbeenPwdValidator(Validator):
    """Check leak password in network: password (str) """

    def __init__(self, password: str):
        """

        :param password: password
        :type password: str
        """
        self.password = password
        self.url = 'https://api.pwnedpasswords.com/range/'
# https://api.pwnedpasswords.com/range/67504 self.url+password[:5]

    def is_valid(self):
        """

        :return: raises or True
        :rtype:
        """
        password = sha1(self.password.encode('utf-8')).hexdigest().upper()
        response = get(self.url+password[:5], timeout=2).text.splitlines()
        for single_response in response:
            hash_password = single_response.split(':')[0]
            numbers_of_leaks = single_response.split(':')[1]
            if hash_password == password[5:]:
                raise WeakPassword(f'Yours password has been leaked {numbers_of_leaks} times.')
            return True


class PasswordValidator(Validator):
    """Main class. Password validator password (str) """
    def __init__(self, password):
        self.password = password
        self.check_rules = []
        self.validators = [
            LengthValidator,
            HasNumberValidator,
            HasSpecialCharactersValidator,
            HasUpperCharactersValidator,
            HasLowerCharacterValidator,
            HaveIbeenPwdValidator
        ]

    def is_valid(self):
        for class_name in self.validators:
            validator = class_name(self.password)
            self.check_rules.append(validator.is_valid())

            if all(self.check_rules):
                print(self.password)
                raise StrongPassword('Password is strong')


class LoadPassword:
    """Load password from file"""
    def __init__(self):
        self.passwords = str
        self.path_password = 'Fake password.txt'
        self.path_validate_password = 'Validate password.txt'
        self.get()

    def get(self):
        """method get password from file"""
        with open(self.path_password, 'r', encoding='utf-8') as readfile, \
                open(self.path_validate_password, 'a', encoding='utf-8') as validate_file:
            validate_file.truncate(0)
            self.passwords = readfile.readlines()

            for password in self.passwords:
                try:
                    password = password.strip('\n')
                    print(f'Check {password}')
                    PasswordValidator(password).is_valid()
                except WeakPassword as msg:
                    print(f'{password}  ' + str(msg))
                    print('_________________')

                except StrongPassword:
                    print(f'Password {password} is strong.')
                    validate_file.writelines(f'Password: {password} is strong.')


if __name__ == '__main__':
    HaveIbeenPwdValidator('Adamo').is_valid()
