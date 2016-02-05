/**
 * Created by Hahn on 2015-11-05.
 */
var ReadOnlyPopupTemplate = _.template('\
    <div class="modal-dialog privacy"><div class="modal-content">\
    <% if (title) { %>\
      <div class="modal-header">\
        <% if (allowHeaderCancel) { %>\
          <a class="close ok">&times;</a>\
        <% } %>\
        <h4><%=title%></h4>\
      </div>\
    <% } %>\
    <div class="modal-body">{{content}}</div>\
    <% if (showFooter) { %>\
      <div class="modal-footer">\
        <% if (allowCancel) { %>\
          <% if (cancelText) { %>\
            <a href="#" class="btn cancel">{{cancelText}}</a>\
          <% } %>\
        <% } %>\
        <a href="#" class="btn ok btn-primary"><%=okText%></a>\
      </div>\
    <% } %>\
    </div></div>\
')