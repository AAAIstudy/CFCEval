from __future__ import absolute_import
import copy
import logging

import six.moves.urllib.error  # pylint: disable=import-error
import six.moves.urllib.parse  # pylint: disable=import-error
import six.moves.urllib.request  # pylint: disable=import-error
import six
from xblockutils.resources import ResourceLoader
from .utils import (
    Constants, SHOWANSWER, DummyTranslationService, FeedbackMessage,
    FeedbackMessages, ItemStats, StateMigration, _clean_data, _, sanitize_html
)

# Globals ###########################################################

loader = ResourceLoader(__name__)
logger = logging.getLogger(__name__)


def student_view_data(self, context=None):
    """
    Get the configuration data for the student_view.
    The configuration is all the settings defined by the author, except for correct answers
    and feedback.
    """

    def items_without_answers():
        """
        Removes feedback and answer from items
        """
        items = copy.deepcopy(self.data.get('items', ''))
        for item in items:
            del item['feedback']
            # Use item.pop to remove both `item['zone']` and `item['zones']`; we don't have
            # a guarantee that either will be present, so we can't use `del`. Legacy instances
            # will have `item['zone']`, while current versions will have `item['zones']`.
            item.pop('zone', None)
            item.pop('zones', None)
            # Fall back on "backgroundImage" to be backward-compatible.
            image_url = item.get('imageURL') or item.get('backgroundImage')
            if image_url:
                item['expandedImageURL'] = self._expand_static_url(image_url)
            else:
                item['expandedImageURL'] = ''
            item['displayName'] = sanitize_html(item.get('displayName', ''))
        return items

    return {
        "block_id": six.text_type(self.scope_ids.usage_id),
        "display_name": sanitize_html(self.display_name),
        "type": self.CATEGORY,
        "weight": self.weight,
        "mode": self.mode,
        "zones": self.zones,
        "max_attempts": self.max_attempts,
        "graded": getattr(self, 'graded', False),
        "weighted_max_score": self.max_score() * self.weight,
        "max_items_per_zone": self.max_items_per_zone,
        # SDK doesn't supply url_name.
        "url_name": getattr(self, 'url_name', ''),
        "display_zone_labels": self.data.get('displayLabels', False),
        "display_zone_borders": self.data.get('displayBorders', False),
        "display_zone_borders_dragging": self.data.get('displayBordersDragging', False),
        "items": items_without_answers(),
        "title" : sanitize_html(self.title),
        "description": sanitize_html(self.description),
        "instructions": sanitize_html(self.instructions),
        "show_correctness": self.data.get('showCorrectness', False),
        "show_solution_on_ incorrect": self.data.get('showSolutionOnIncorrect', False),
        "show_feedback_on_incorrect": self.data.get('showFeedbackOnIncorrect', False),
        "show_feedback_on_correct": self.data.get('showFeedbackOnCorrect', False),
        "show_solution_on_hint": self.data.get('showSolutionOnHint', False),
        "show_hints": self.data.get('showHints', False),
        "hint_list": [sanitize_html(item) for item in self.data.get('hintList', [])],
        "allow_multiple_attempts": self.data.get('allowMultipleAttempts', True),
        "show_correctness_details": self.data.get('showCorrectnessDetails', False),
        "show_solution_on_click": self.data.get('showSolutionOnClick', False),
        "show_feedback_on_click": self.data.get('showFeedbackOnClick', False),
        "allow_practice_session": self.data.get('allowPracticeSession', True),
        "allow_multiple_attempts_in_practice_session": self.data.get('allowMultipleAttemptsInPracticeSession', False),
        "show_correctness_details_in_practice_session": self.data.get('showCorrectnessDetailsInPracticeSession', False),
        "show_solution_on_click_in_practice_session": self.data.get('showSolutionOnClickInPracticeSession', False),
        "show_feedback_on_click_in_practice_session": self.data.get('showFeedbackOnClickInPracticeSession', False),
        "allow_hints_in_practice_session": self.data.get('allowHintsInPracticeSession', True),
        "show_solution_on_hint_in_practice_session": self.data.get('showSolutionOnHintInPracticeSession', False),
        "show_feedback_on_hint_in_practice_session": self.data.get('showFeedbackOnHintInPracticeSession', False),
        "allow_partial_scoring_in_practice_session": self.data.get('allowPartialScoringInPracticeSession', True),
        "allow_multiple_attempts_in_assessment": self.data.get('allowMultipleAttemptsInAssessment', False),
        "show_correctness_details_in_assessment": self.data.get('showCorrectnessDetailsInAssessment', False),
        "show_solution_on_click_in_assessment": self.data.get('showSolutionOnClickInAssessment', False),
        "show_feedback_on_click_in_assessment": self.data.get('showFeedbackOnClickInAssessment', False),
        "allow_hints_in_assessment": self.data.get('allowHintsInAssessment', True),
        "show_solution_on_hint_in_assessment": self.data.get('showSolutionOnHintInAssessment', False),
        "show_feedback_on_hint_in_assessment": self.data.get('showFeedbackOnHintInAssessment', False),
        "allow_partial_scoring_in_assessment": self.data.get('allowPartialScoringInAssessment', True),
        "allow_multiple_attempts_in_practice_session_with_hints": self.data.get('allowMultipleAttemptsInPracticeSessionWithHints', False),
        "show