from main import HasNumberValidator, WeakPassword, \
    HasSpecialCharactersValidator, HasUpperCharactersValidator, \
    HasLowerCharacterValidator, LengthValidator, HaveIbeenPwdValidator
import pytest


def test_positive_has_number_validator():
    assert HasNumberValidator("1AEe5VASDV").is_valid() is True


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


def test_have_i_been_pwd_validator_dont_find(requests_mock):
    # 675040F865345FA218494E476477418735135CE4 -> 'Adamo'
    data = '00232BC8113BA387E082179F8212DF7FEAF:2\n037001F472ECEF25640E1592C1A550927D2:8'
    requests_mock.get('https://api.pwnedpasswords.com/range/67504', text=data)
    assert HaveIbeenPwdValidator('Adamo').is_valid() is True


def test_have_i_been_pwd_validator_find(requests_mock):
    # 675040F865345FA218494E476477418735135CE4 -> 'Adamo'
    data = '00232BC8113BA387E082179F8212DF7FEAF:2\n0F865345FA218494E476477418735135CE4:9'
    requests_mock.get('https://api.pwnedpasswords.com/range/67504', text=data)
    with pytest.raises(WeakPassword) as msg:
        HaveIbeenPwdValidator('Adamo').is_valid()
        assert msg == 'Yours password has been leaked 9 times.'
