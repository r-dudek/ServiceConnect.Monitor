﻿require.config({
    urlArgs: "version=0.0.1",
    paths: {
        "jquery": 'bower_components/jquery/dist/jquery',
        "underscore": 'bower_components/underscore/underscore',
        "backbone": 'bower_components/backbone/backbone',
        "bootstrap": 'bower_components/bootstrap/dist/js/bootstrap',
        "toastr": "bower_components/toastr/toastr",
        'backbone.stickit': 'bower_components/backbone.stickit/backbone.stickit',
        'backgrid': 'bower_components/backgrid/lib/backgrid',
        'select2': 'bower_components/select2/select2',
        'backbone-pageable': 'bower_components/backbone-pageable/lib/backbone-pageable',
        'backgrid-filter': 'bower_components/backgrid-filter/backgrid-filter',
        'backgrid-paginator': 'bower_components/backgrid-paginator/backgrid-paginator',
        'moment': "bower_components/moment/moment",
        "vis": "bower_components/vis/dist/vis"
    },
    shim: {
        'backbone-pageable': {
            deps: ["backbone", "underscore", "jquery"]
        },
        'backgrid-filter': {
            deps: ["backbone", "underscore", "jquery", "backgrid"]
        },
        'backgrid-paginator': {
            deps: ["backbone", "underscore", "jquery", "backgrid"]
        },
        'select2': {
            deps: ["jquery"]
        },
        'backgrid': {
            deps: ["jquery", "backbone", "underscore"],
            exports: "Backgrid"
        },
        "bootstrap": {
            deps: ["jquery"]
        },
        'jquery': {
            deps: [],
            exports: '$'
        },
        'backbone': {
            deps: ["underscore", "jquery"],
            exports: "Backbone"
        },
        'underscore': {
            exports: "_"
        },
        'backbone.stickit': {
            deps: ["backbone", "underscore", "jquery"]
        }
    },
    waitSeconds: 200
});

require(['backbone',
         'jquery',
         'toastr',
         'app/routers/main',
         'bootstrap',
         'backgrid-paginator',
         'app/helpers/backbone.extensions',
         'app/helpers/underscore.extensions',
         'app/helpers/backgrid.extensions',
         "vis"],
function (Backbone, $, toastr, Router) {
    Backbone.Application = {};
    Backbone.Application.Router = new Router();
    toastr.options = {
        "closeButton": false,
        "debug": false,
        "positionClass": "toast-bottom-right",
        "onclick": null,
        "showDuration": "300",
        "hideDuration": "1000",
        "timeOut": "5000",
        "extendedTimeOut": "1000",
        "showEasing": "swing",
        "hideEasing": "linear",
        "showMethod": "fadeIn",
        "hideMethod": "fadeOut"
    };
    Backbone.history.start();
});
