/**
 * Created by Hahn on 2015-11-26.
 */

// Education Schedule View
var EducationScheduleView = Backbone.View.extend({
    el: '<div id="education-schedule"></div>',
    html: 'education-schedule.html',
    initialize: function(){
    },
    render: function(){
        $(this.el).html(App.comm.getHtml(this.html));
    }
});