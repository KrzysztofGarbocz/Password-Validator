from abc import ABC, abstractmethod
from string import digits, punctuation, ascii_uppercase, ascii_lowercase


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
    """Check password length: password (str) """
    def __init__(self, password):
        self.password = password

    def is_valid(self):
        if len(self.password) < 7:
            raise WeakPassword('Too short password')


class Have_I_been_Pwd_Validator(Validator):
    """Check leak password in network: password (str) """
    def __init__(self, password):
        self.password = password

    def is_valid(self):
        pass


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
                raise StrongPassword('Password is strong')
