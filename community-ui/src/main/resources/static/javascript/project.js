/**
 * Created by Hahn on 2015-11-26.
 */
// Project Views
var ProjectOverviewView = Backbone.View.extend({
    el: '<div id="project-overview"></div>',
    html: 'project-overview.html',
    initialize: function(){
    },
    render: function(){
        $(this.el).html(App.comm.getHtml(this.html));
    }
});
var ProjectCoreView = Backbone.View.extend({
    el: '<div id="project-core"></div>',
    html: 'project-core.html',
    initialize: function(){
    },
    render: function(){
        $(this.el).html(App.comm.getHtml(this.html));
    }
});
var ProjectCodeGeneratorView = Backbone.View.extend({
    el: '<div id="project-code-generator"></div>',
    html: 'project-code-generator.html',
    initialize: function(){
    },
    render: function(){
        $(this.el).html(App.comm.getHtml(this.html));
    }
});
var ProjectQueryManagerView = Backbone.View.extend({
    el: '<div id="project-query-manager"></div>',
    html: 'project-query-manager.html',
    initialize: function(){
    },
    render: function(){
        $(this.el).html(App.comm.getHtml(this.html));
    }
});
var ProjectOdenView = Backbone.View.extend({
    el: '<div id="project-oden"></div>',
    html: 'project-oden.html',
    initialize: function(){
    },
    render: function(){
        $(this.el).html(App.comm.getHtml(this.html));
    }
});
var ProjectLogManagerView = Backbone.View.extend({
    el: '<div id="project-log-manager"></div>',
    html: 'project-log-manager.html',
    initialize: function(){
    },
    render: function(){
        $(this.el).html(App.comm.getHtml(this.html));
    }
});
var ProjectBatchView = Backbone.View.extend({
    el: '<div id="project-batch"></div>',
    html: 'project-batch.html',
    initialize: function(){
    },
    render: function(){
        $(this.el).html(App.comm.getHtml(this.html));
    }
});
var ProjectIamView = Backbone.View.extend({
    el: '<div id="project-iam"></div>',
    html: 'project-iam.html',
    initialize: function(){
    },
    render: function(){
        $(this.el).html(App.comm.getHtml(this.html));
    }
});
var ProjectMonitoringView = Backbone.View.extend({
    el: '<div id="project-monitoring"></div>',
    html: 'project-monitoring.html',
    initialize: function(){
    },
    render: function(){
        $(this.el).html(App.comm.getHtml(this.html));
    }
});