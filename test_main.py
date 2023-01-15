from main import HasNumberValidator, WeakPassword, HasSpecialCharactersValidator, HasUpperCharactersValidator, \
    HasLowerCharacterValidator, LengthValidator, Have_I_been_Pwd_Validator
import pytest


def test_positive_has_number_validator():
        validator = HasNumberValidator("1AEe5VASDV").is_valid()
        assert validator is True


def test_negative_has_number_validator():
    with pytest.raises(WeakPassword) as msg:
        HasNumberValidator("AEeVASDV").is_valid()
        assert msg == 'Password dont have number'


def test_positive_has_spec_char_validator():
        validator = HasSpecialCharactersValidator("!AEe5VASDV").is_valid()
        assert validator is True


def test_negative_spec_char_validator():
    with pytest.raises(WeakPassword) as msg:
        HasSpecialCharactersValidator("AEeVASDV").is_valid()
        assert msg == 'Password dont have special character'


def test_positive_has_upper_char_validator():
    validator = HasUpperCharactersValidator("!AEe5VefwefV").is_valid()
    assert validator is True


def test_negative_upper_char_validator():
    with pytest.raises(WeakPassword) as msg:
        HasUpperCharactersValidator("alamakota").is_valid()
        assert msg == 'Password dont have upper character'


def test_positive_has_lower_char_validator():
    validator = HasLowerCharacterValidator("!AEe5VefwefV").is_valid()
    assert validator is True


def test_negative_lower_char_validator():
    with pytest.raises(WeakPassword) as msg:
        HasLowerCharacterValidator("ALA_MA KOTA").is_valid()
        assert msg == 'Password dont have lower character'


def test_positive_has_length_char_validator():
    validator = LengthValidator("12345678").is_valid()
    assert validator is True


def test_negative_length_char_validator():
    with pytest.raises(WeakPassword) as msg:
        LengthValidator("123457").is_valid()
        assert msg == 'Too short password'

#def test_have_i_been_pwd_validator():


