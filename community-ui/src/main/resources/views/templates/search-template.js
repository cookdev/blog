var searchResultItemTemplate = _.template('<li>\
    <a href="<%= location %>" target="_blank">\
        <h3>\
        <% if (contentType == "application/pdf") { %>\
            <i class="fa fa-file-pdf-o"></i>\
        <% } %>\
        <% if (title == "") { %>\
            <%= location %>\
        <% } else { %>\
            <%= title %>\
        <% } %>\
        </h3>\
    </a>\
    <p><%= location %></p>\
    <p><%= summary %></p>\
</li>');