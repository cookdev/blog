var noticeItemTemplate = _.template ("\
    <article class='list-item panel panel-default'>\
        <div class='item-body panel-body'>\
            <div class='title'><a href='#notice/editor/<%= noticeId %>' class='notice-update-editor'><h2><%= title %></h2></a></div>\
            <div class='date'><%= date %></div>\
            <div class='content'><%= content %></div>\
        </div>\
    </article>\
    ")
