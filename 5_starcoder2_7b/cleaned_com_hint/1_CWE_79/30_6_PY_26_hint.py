from .utils import (sanitize_html)
@staticmethod
def _present_feedback(feedback_messages):
    """
    Transforms feedback messages into format expected by frontend code
    """
    return [
        {"message ": sanitize_html(msg), "type": type} for msg, type in feedback_messages