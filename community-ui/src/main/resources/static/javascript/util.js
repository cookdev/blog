/*
* common Utilz
*
* */
App.comm.rootForum = "https://forum.ssc.com";
App.comm.rootBlog = "https://blog.ssc.com";

App.comm.getHtml = function(url){
    var getFile = $.ajax({
        url: url,
        async: false,
        success: function (data) {
            return data;
        }
    });

    return getFile.responseText;
}

App.comm.getParameterByName = function(name) {
    name = name.replace(/[\[]/, "\\[").replace(/[\]]/, "\\]");
    var regex = new RegExp("[\\?&]" + name + "=([^&#]*)"),
        results = regex.exec(window.location.href);
    return results === null ? "" : decodeURIComponent(results[1].replace(/\+/g, " "));
}