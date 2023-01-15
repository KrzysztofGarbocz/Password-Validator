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
        pass


class HasNumberValidator(Validator):
    """Check number in password (str) """
    def __init__(self, password):
        self.password = password

    def is_valid(self):
        if any([True for char in self.password if char in digits]):
            return True
        else:
            raise WeakPassword('Password dont have number')


class HasSpecialCharactersValidator(Validator):
    """Check special characters in password (str) """
    def __init__(self, password):
        self.password = password

    def is_valid(self):
        if any([True for char in self.password if char in punctuation]):
            return True
        else:
            raise WeakPassword('Password dont have special character')


class HasUpperCharactersValidator(Validator):
    """Check upper case in password (str) """
    def __init__(self, password):
        self.password = password

    def is_valid(self):
        if any([True for char in self.password if char in ascii_uppercase]):
            return True
        else:
            raise WeakPassword('Password dont have upper character')


class HasLowerCharacterValidator(Validator):
    """Check lower case in password (str) """
    def __init__(self, password):
        self.password = password

    def is_valid(self):
        if any([True for char in self.password if char in ascii_lowercase]):
            return True
        else:
            raise WeakPassword('Password dont have lower character')


class LengthValidator(Validator):
    """Check password length: password (str) min length is 8 char"""
    def __init__(self, password):
        self.password = password

    def is_valid(self):
        if len(self.password) < 8:
            raise WeakPassword('Too short password')
        else:
            return True


class Have_I_been_Pwd_Validator(Validator):
    """Check leak password in network: password (str) """
    def __init__(self, password: str):
        self.password = password
        self.url = 'https://api.pwnedpasswords.com/range/'

    def is_valid(self):
        password = sha1(self.password.encode('utf-8')).hexdigest().upper()
        responce = get(self.url+password[:5]).text.splitlines()
        for single_responce in responce:
            hash = single_responce.split(':')[0]
            numbers_of_leaks = single_responce.split(':')[1]
            if hash == password[5:]:
                raise WeakPassword(f'Yours password has been leaked {numbers_of_leaks} times.')


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
            Have_I_been_Pwd_Validator
        ]

    def is_valid(self):
        for class_name in self.validators:
            validator = class_name(self.password)
            self.check_rules.append(validator.is_valid())

            if all(self.check_rules):
                print(self.password)
                raise StrongPassword('Password is strong')
class LoadPassword:
    def __init__(self):
        self.passwords = str
        self.path_passowrd = 'Fake password.txt'
        self.path_validate_password = 'Validate password.txt'
        self.get()
    def get(self):
        with open(self.path_passowrd,'r') as readfile, open(self.path_validate_password,'a') as validateFile:
           # validateFile.truncate(0)
            self.passwords = readfile.readlines()

            for password in self.passwords:
                try:
                    password = password.strip('\n')
                    print(f'Check {password}')
                    PasswordValidator(password).is_valid()
                except WeakPassword as msg:
                    print(f'{password}  ' + str(msg))
                    print('_________________')

                except StrongPassword as msg:
                    print(f'Password {password} is strong.')
                    validateFile.writelines(f'Password: {password} is strong.')



if __name__ == '__main__':
    LoadPassword()