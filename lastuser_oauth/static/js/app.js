// Detect timezone
$(function() {
  if ($.cookie('timezone') === null) {
    $.cookie('timezone', jstz.determine().name(), {path: '/'});
  }
});
