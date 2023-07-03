import re


class ValidatorSettings:
    username_pattern = r"^[a-zA-Z0-9-_]+$"
    email_pattern = r"^(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\x22(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*\x22)@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])$"
    password_special_character_string = "!\"#\$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
    password_special_character = r"[!\"#\$%&'()*+,-.\/:;<=>?@[\\\]^_`{|}~]"
    password_small_character = r"[a-z]"
    password_large_character = r"[A-Z]"
    password_numeric_character = r"[0-9]"
    phone_number_invalid_chars = r"( |-)"
    phone_number_international_format = r"^\+[0-9]{2,29}$"
    MAX_USERNAME_LENGTH = 32
    MAX_EMAIL_LENGTH = 254
    MIN_PASSWORD_LENGTH = 6
    MAX_PASSWORD_LENGTH = 50
    MAX_PHONE_NUMBER_LENGTH = 30

class Validators:
    @staticmethod
    def none_check(v, input_type = "Input"):
        return f'{input_type} must not be None' if (v is None) else None
    
    def empty_check(v, input_type = "Input"):
        return f'{input_type} must contain at least one character' if (v is None or len(v) == 0) else None

    USERNAME_PATTERN_MISMATCH_ERROR_MESSAGE = "Input is not a valid username"
    @staticmethod
    def username_check(v, check_username_pattern = True, perform_none_check = False, perform_empty_check = True):
        if (perform_none_check):
            none_check_res = Validators.none_check(v, input_type = "Username")
            if (none_check_res is not None): return none_check_res
        elif(v is None): return None

        if (perform_empty_check):
            empty_check_res = Validators.empty_check(v, input_type = "Username")
            if (empty_check_res is not None): return empty_check_res

        if (check_username_pattern and (re.search(ValidatorSettings.username_pattern, v) is None)):
            return Validators.USERNAME_PATTERN_MISMATCH_ERROR_MESSAGE
        if (len(v) > ValidatorSettings.MAX_USERNAME_LENGTH):
            return f'Username must have no more than {ValidatorSettings.MAX_USERNAME_LENGTH} characters'
        return None
    
    EMAIL_PATTERN_MISMATCH_ERROR_MESSAGE = "Input is not a valid email"
    def email_check(v, check_email_pattern = True, perform_none_check = False, perform_empty_check = True):
        if (perform_none_check):
            none_check_res = Validators.none_check(v, input_type = "Email")
            if (none_check_res is not None): return none_check_res
        elif(v is None): return None
        
        if (perform_empty_check):
            empty_check_res = Validators.empty_check(v, input_type = "Username")
            if (empty_check_res is not None): return empty_check_res

        if (check_email_pattern and (re.search(ValidatorSettings.email_pattern, v) is None)):
            return Validators.EMAIL_PATTERN_MISMATCH_ERROR_MESSAGE
        if (len(v) > ValidatorSettings.MAX_EMAIL_LENGTH):
            return f"Email must be no more than {ValidatorSettings.MAX_EMAIL_LENGTH} characters long"
        return None

    def password_check(v, perform_none_check = False, perform_empty_check = True):
        if (perform_none_check):
            none_check_res = Validators.none_check(v, input_type = "Password")
            if (none_check_res is not None): return none_check_res
        elif(v is None): return None

        if (perform_empty_check):
            empty_check_res = Validators.empty_check(v, input_type = "Username")
            if (empty_check_res is not None): return empty_check_res

        if(len(v) < ValidatorSettings.MIN_PASSWORD_LENGTH or len(v) > ValidatorSettings.MAX_PASSWORD_LENGTH):
            return f'Password must contain {ValidatorSettings.MIN_PASSWORD_LENGTH}-{ValidatorSettings.MAX_PASSWORD_LENGTH} characters'
        if(re.search(ValidatorSettings.password_special_character, v) is None):
            return f'Password must contain one of the following special characters: {ValidatorSettings.password_special_character_string}'
        if(re.search(ValidatorSettings.password_small_character, v) is None):
            return 'Password must contain at least one lowercase character'
        if(re.search(ValidatorSettings.password_large_character, v) is None):
            return 'Password must contain at least one uppercase character'
        if(re.search(ValidatorSettings.password_numeric_character, v) is None):
            return 'Password must contain at least one number'
        return None

    def phone_number_check(v, perform_none_check = False, perform_empty_check = True):
        if (perform_none_check):
            none_check_res = Validators.none_check(v, input_type = "Phone number")
            if (none_check_res != None): return none_check_res
        elif(v is None): return None

        if (perform_empty_check):
            empty_check_res = Validators.empty_check(v, input_type = "Username")
            if (empty_check_res is not None): return empty_check_res

        if(len(v) > ValidatorSettings.MAX_PHONE_NUMBER_LENGTH):
            return f'Phone number must contain at most {ValidatorSettings.MAX_PHONE_NUMBER_LENGTH} characters'
        if(re.search(ValidatorSettings.phone_number_invalid_chars, v) is not None):
            return 'Phone number must not contain spaces or dashes'
        if(re.search(ValidatorSettings.phone_number_international_format, v) is None):
            return 'Phone number must be in international format (+\{countryCode\}\{number\}, without the braces)'
        return None

    def multi_validator(validator_results):
        for validator_result in validator_results:
            if(validator_result is not None):
                return validator_result
        return None
