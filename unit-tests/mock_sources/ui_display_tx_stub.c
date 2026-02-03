#include "ui_display_tx.h"
#include "ui_utils.h"
#include "ui_warnings.h"

void tx_review_cleanup(void) {
    ui_pairs_cleanup();
    ui_free_warnings();
}
