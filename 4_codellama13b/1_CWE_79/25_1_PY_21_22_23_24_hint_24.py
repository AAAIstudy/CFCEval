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
        "title": sanitize_html(self.display_name),
        "show_title": self.show_title,
        "problem_text" : sanitize_html(self.data.get('problemText', '')),
        "instructions": sanitize_html(self.data.get('instructions', '')),
        "show_solution": self.show_solution,
        "show_feedback": self.show_feedback,
        "allow_multiple_attempts": self.allow_multiple_attempts,
        "allow_reset": self.allow_reset,
        "allow_skip": self.allow_skip,
        "allow_undo": self.allow_undo,
        "show_correctness": self.show_correctness,
        "show_feedback_details": self.show_feedback_details,
        "show_hints": self.show_hints,
        "show_solution_on_finish": self.show_solution_on_finish,
        "show_score_breakdown": self.show_score_breakdown,
        "show_correctness_details": self.show_correctness_details,
        "show_hints_details": self.show_hints_details,
        "allow_late_submission": self.allow_late_submission,
        "allow_autosubmit": self.allow_autosubmit,
        "allow_anonymous_submissions": self.allow_anonymous_submissions,
        "show_correctness_details_in_report": self.show_correctness_details_in_report,
        "show_hints_details_in_report": self.show_hints_details_in_report,
        "allow_multiple_attempts_in_report": self.allow_multiple_attempts_in_report,
        "allow_anonymous_submissions_in_report": self.allow_anonymous_submissions_in_report,
        "show_correctness_details_in_report_for_instructor": self.show_correctness_details_in_report_for_instructor,
        "show_hints_details_in_report_for_instructor": self.show_hints_details_in_report_for_instructor,
        "allow_multiple_attempts_in_report_for_instructor": self.allow_multiple_attempts_in_report_for_instructor,
        "allow_anonymous_submissions_in_report_for_instructor": self.allow_anonymous_submissions_in_report_for_instructor,
        "show_correctness_details_in_report_for_learner": self.show_correctness_details_in_report_for_learner,
        "show_hints_details_in_report_for_learner": self.show_hints_details_in_report_for_learner,
        "allow_multiple_attempts_in_report_for_learner": self.allow_multiple_attempts_in_report_for_learner,
        "allow_anonymous_submissions_in_report_for_learner": self.allow_anonymous_submissions_in_report_for_learner,
        "show_correctness_details_in_report_for_instructor_and_learner": self.show_correctness_details_in_report_for_instructor_and_learner,
        "show_hints_details_in_report_for_instructor_and_learner": self.show_hints_details_in_report_for_instructor_and_learner,
        "allow_multiple_attempts_in_report_for_instructor_and_learner": self.allow_multiple_attempts_in_report_for_instructor_and_learner,
        "allow_anonymous_submissions_in_report_for_instructor_and_learner": self.allow_anonymous_submissions_in_report_for_instructor_and_learner,
        "show_correctness_details_in_report_for_instructor_and_learner_during_assessment": self.show_correctness_details_in_report_for_instructor_and_learner_during_assessment,
        "show_hints_details_in_