# This is used to fix some corner cases in some projects.

CURRENT_ID = 0


def set_current_id(id):
    global CURRENT_ID
    CURRENT_ID = id


def get_current_id():
    return CURRENT_ID


def apply_valid_pointer_check_fix():
    return get_current_id() in ["66742", "67354", "e5321", "e3623"]

def apply_valid_pointer_check_post_fix():
    return get_current_id() in ["e5321", "e3623"]


def apply_66163_fix():
    return get_current_id() == "66163"
