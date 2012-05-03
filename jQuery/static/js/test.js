$(function(){

    $(document).slapos();
    
    module("Cross-domain Tests");
    test("200 response", function(){
        expect(1);
        stop(1);
        $.ajax({
            url: 'http://sheldy.com:5000/200',
            complete: function() { start(); },
            statusCode: {
                200: function(){ ok(true, "should get 200 status");}
            }});
    });
    
    test("404 response", function(){
        expect(1);
        stop(1);
        $.ajax({
            url: 'http://sheldy.com:5000/request',
            complete: function() { start(); },
            statusCode: {
                404: function(xhr){ ok(true, "should get 404 error status status="+xhr.status); },
                0: function(){ ok(false, "should get 404 not but receive 0"); }
            }});
    });

    module("Local Ajax Tests", {
        setup: function(){
            this.server = sinon.sandbox.useFakeServer();
            this.header = {"Content-Type":"application/json; charset=utf-8"};
            this.error = [409, this.header, 'ERROR'];
        },
        teardown: function(){
            this.server.restore();
        }
    });

    test("Requesting a new instance", function(){
        var callback = this.spy();
        this.spy(jQuery, 'ajax');
        
        url = "/request";
        responseBody = [{instance_id: "anId",status: "started",connection: {}}];
        response = [201, this.header, JSON.stringify(responseBody)];
        this.server.respondWith("POST", url, response);
        
        $(document).slapos('newInstance', '', callback);
        this.server.respond();
        
        equal(jQuery.ajax.getCall(0).args[0].url, $(document).slapos('store', 'host')+url);
        ok(callback.calledOnce, "callback should be called");
        ok(callback.calledWith(responseBody), 'should return mainly id and status of an instance');
    });
    
    test("Requesting a new instance - Fail", function(){
        var callback = this.spy();
        this.spy(jQuery, 'ajax');
        
        url = "/request";
        this.server.respondWith("POST", url, this.error);
        
        $(document).slapos('newInstance', '', callback);
        this.server.respond();

        equal(jQuery.ajax.getCall(0).args[0].url, $(document).slapos('store', 'host')+url);
        ok(!callback.calledOnce, "callback should not be called");
    });
    
    test("Deleting an instance", function(){
        var callback = this.spy();
        this.spy(jQuery, 'ajax');

        response = [202, this.header, ''];
        this.server.respondWith("DELETE", /\/instance\/(\w+)/, response);
        
        $(document).slapos('deleteInstance', 'id', callback);
        this.server.respond();
        
        equal(jQuery.ajax.getCall(0).args[0].url, $(document).slapos('store', 'host')+'/instance/id');
        ok(callback.calledOnce, "callback should be called");
    });

    test("Deleting an instance - Fail", function(){
        
        var callback = this.spy();
        this.spy(jQuery, 'ajax');
        
        this.server.respondWith("DELETE", /\/instance\/(\w+)/, this.error);
        
        $(document).slapos('deleteInstance', 'id', callback);
        this.server.respond();
        
        equal(jQuery.ajax.getCall(0).args[0].url, $(document).slapos('store', 'host')+'/instance/id');
        ok(!callback.calledOnce, "callback should not be called");
    });
    
    test("Get instance information", function(){
        
        var callback = this.spy();
        this.spy(jQuery, 'ajax');
        
        responseBody = [{instance_id: "anId", status: "start", software_release: "http://example.com/example.cfg",
                        software_type: "type_provided_by_the_software", slave: "False", connection: {
                            custom_connection_parameter_1: "foo",
                            custom_connection_parameter_2: "bar"},
                        parameter: {Custom1: "one string", Custom2: "one float",
                                    Custom3: ["abc", "def"]},
                        sla: {computer_id: "COMP-0"},
                        children_id_list: ["subinstance1", "subinstance2"],
                        partition: {public_ip: ["::1", "91.121.63.94"], private_ip: ["127.0.0.1"],
                                    tap_interface: "tap2"}}];
        response = [200, this.header, JSON.stringify(responseBody)];
        this.server.respondWith("GET", /\/instance\/(\w+)/, response);
        
        $(document).slapos('getInstance', 'id', callback);
        this.server.respond();
        
        equal(jQuery.ajax.getCall(0).args[0].url, $(document).slapos('store', 'host')+'/instance/id');
        ok(callback.calledOnce, "callback should be call");
        ok(callback.calledWith(responseBody), "should return informations of an instance");
    });

    test("Get instance information - Fail", function(){
        
        var callback = this.spy();
        this.spy(jQuery, 'ajax');
        
        this.server.respondWith("GET", /\/instance\/(\w+)/, this.error);
        
        $(document).slapos('getInstance', 'id', callback);
        this.server.respond();
        
        equal(jQuery.ajax.getCall(0).args[0].url, $(document).slapos('store', 'host')+'/instance/id');
        ok(!callback.calledOnce, "callback should not be called");
    });

    test("Get instance authentication certificates", function(){
        
        var callback = this.spy();
        this.spy(jQuery, 'ajax');
        
        responseBody = [{ ssl_key: "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADAN...h2VSZRlSN\n-----END PRIVATE KEY-----",
                          ssl_certificate: "-----BEGIN CERTIFICATE-----\nMIIEAzCCAuugAwIBAgICHQI...ulYdXJabLOeCOA=\n-----END CERTIFICATE-----"}];
        response = [200, this.header, JSON.stringify(responseBody)];
        this.server.respondWith("GET", /\/instance\/(\w+)\/certificate/, response);
        
        $(document).slapos('getInstanceCert', 'id', callback);
        this.server.respond();
        
        equal(jQuery.ajax.getCall(0).args[0].url, $(document).slapos('store', 'host')+'/instance/id/certificate');
        ok(callback.calledOnce, "callback call");
        ok(callback.calledWith(responseBody));
    });

    test("Get instance authentication certificates - Fail", function(){
        
        var callback = this.spy();
        this.spy(jQuery, 'ajax');
        
        this.server.respondWith("GET", /\/instance\/(\w+)\/certificate/, this.error);
        
        $(document).slapos('getInstanceCert', 'id', callback);
        this.server.respond();
        
        equal(jQuery.ajax.getCall(0).args[0].url, $(document).slapos('store', 'host')+'/instance/id/certificate');
        ok(!callback.calledOnce, "callback should not be called");
    });
    
    test("Bang instance", function(){
        
        var callback = this.spy();
        this.spy(jQuery, 'ajax');
        
        response = [200, this.header, ''];
        this.server.respondWith("POST", /\/instance\/(\w+)\/bang/, response);
        
        data = '';
        $(document).slapos('bangInstance', 'id', data, callback);
        this.server.respond();
        
        equal(jQuery.ajax.getCall(0).args[0].url, $(document).slapos('store', 'host')+'/instance/id/bang');
        ok(callback.calledOnce, "callback should be called");
    });

    test("Bang instance - Fail", function(){
        
        var callback = this.spy();
        this.spy(jQuery, 'ajax');
        
        this.server.respondWith("POST", /\/instance\/(\w+)\/bang/, this.error);
        
        $(document).slapos('bangInstance', 'id', data, callback);
        this.server.respond();
        
        equal(jQuery.ajax.getCall(0).args[0].url, $(document).slapos('store', 'host')+'/instance/id/bang');
        ok(!callback.calledOnce, "callback should not be called");
    });
    
    test("Modifying instance", function(){
        
        var callback = this.spy();
        this.spy(jQuery, 'ajax');
        
        response = [200, this.header, ''];
        this.server.respondWith("PUT", /\/instance\/(\w+)/, response);
        
        data = '';
        $(document).slapos('editInstance', 'id', data, callback);
        this.server.respond();
        
        equal(jQuery.ajax.getCall(0).args[0].url, $(document).slapos('store', 'host')+'/instance/id');
        ok(callback.calledOnce, "callback should be called");
    });

    test("Modifying instance - Fail", function(){
        
        var callback = this.spy();
        this.spy(jQuery, 'ajax');
        
        this.server.respondWith("PUT", /\/instance\/(\w+)/, this.error);
        
        $(document).slapos('editInstance', 'id', '', callback);
        this.server.respond();
        
        equal(jQuery.ajax.getCall(0).args[0].url, $(document).slapos('store', 'host')+'/instance/id');
        ok(!callback.calledOnce, "callback should not be called");
    });
    
    test("Register a new computer", function(){
        
        var callback = this.spy();
        this.spy(jQuery, 'ajax');
        
        responseBody = [{computer_id: "COMP-0",
                        ssl_key: "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADAN...h2VSZRlSN\n-----END PRIVATE KEY-----",
                        ssl_certificate: "-----BEGIN CERTIFICATE-----\nMIIEAzCCAuugAwIBAgICHQI...ulYdXJabLOeCOA=\n-----END CERTIFICATE-----"}];
        response = [201, this.header, JSON.stringify(responseBody)];
        this.server.respondWith("POST", "/computer", response);
        
        $(document).slapos('newComputer', '', callback);
        this.server.respond();
        
        equal(jQuery.ajax.getCall(0).args[0].url, $(document).slapos('store', 'host')+'/computer');
        ok(callback.calledOnce, "callback should be called");
        ok(callback.calledWith(responseBody), "should return a computerID, ssl key and ssl certificates");
    });

    test("Register a new computer - Fail", function(){
        
        var callback = this.spy();
        this.spy(jQuery, 'ajax');
        
        this.server.respondWith("POST", "/computer", this.error);
        
        $(document).slapos('newComputer', '', callback);
        this.server.respond();
        
        equal(jQuery.ajax.getCall(0).args[0].url, $(document).slapos('store', 'host')+'/computer');
        ok(!callback.calledOnce, "callback should not be called");
    });
    
    test("Getting computer information", function(){
        
        var callback = this.spy();
        this.spy(jQuery, 'ajax');
        
        responseBody = [{computer_id: "COMP-0",
                        software: [{software_release: "http://example.com/example.cfg",
                                   status: "install"}],
                        partition: [{title: "slapart1",instance_id: "foo",status: "start",
                                     software_release: "http://example.com/example.cfg"},
                                    {title: "slapart2",instance_id: "bar",status: "stop",
                                     software_release: "http://example.com/example.cfg"}]}];
        response = [200, this.header, JSON.stringify(responseBody)];
        this.server.respondWith("GET", /\/computer\/(\w+)/, response);
        
        $(document).slapos('getComputer', 'id', callback);
        this.server.respond();
        
        equal(jQuery.ajax.getCall(0).args[0].url, $(document).slapos('store', 'host')+'/computer/id');
        ok(callback.calledOnce, "callback should be called");
        ok(callback.calledWith(responseBody), "should return informations of a computer");
    });

    test("Getting computer information - Fail", function(){
        
        var callback = this.spy();
        this.spy(jQuery, 'ajax');
        
        this.server.respondWith("GET", /\/computer\/(\w+)/, this.error);
        
        $(document).slapos('getComputer', 'id', callback);
        this.server.respond();
        
        equal(jQuery.ajax.getCall(0).args[0].url, $(document).slapos('store', 'host')+'/computer/id');
        ok(!callback.calledOnce, "callback should not be called");
    });
    
    test("Modifying computer", function(){
        
        var callback = this.spy();
        this.spy(jQuery, 'ajax');
        
        response = [200, this.header, ''];
        this.server.respondWith("PUT", /\/computer\/(\w+)/, response);
        
        $(document).slapos('editComputer', 'id', '', callback);
        this.server.respond();
        
        equal(jQuery.ajax.getCall(0).args[0].url, $(document).slapos('store', 'host')+'/computer/id');
        ok(callback.calledOnce, "callback should be called");
    });
    
    test("Modifying computer - Fail", function(){
        
        var callback = this.spy();
        this.spy(jQuery, 'ajax');
        
        this.server.respondWith("PUT", /\/computer\/(\w+)/, this.error);
        
        $(document).slapos('editComputer', 'id', '', callback);
        this.server.respond();
        
        equal(jQuery.ajax.getCall(0).args[0].url, $(document).slapos('store', 'host')+'/computer/id');
        ok(!callback.calledOnce, "callback should not be called");
    });

    test("Supplying new software", function(){
        
        var callback = this.spy();
        this.spy(jQuery, 'ajax');
        
        response = [200, this.header, ''];
        this.server.respondWith("POST", /\/computer\/(\w+)\/supply/, response);
        
        data = '';
        $(document).slapos('newSoftware', 'id', data, callback);
        this.server.respond();
        
        equal(jQuery.ajax.getCall(0).args[0].url, $(document).slapos('store', 'host')+'/computer/id/supply');
        ok(callback.calledOnce, "callback should be called");
    });

    test("Supplying new software - Fail", function(){
        
        var callback = this.spy();
        this.spy(jQuery, 'ajax');
        
        this.server.respondWith("POST", /\/computer\/(\w+)\/supply/, this.error);
        
        $(document).slapos('newSoftware', 'id', '', callback);
        this.server.respond();
        
        equal(jQuery.ajax.getCall(0).args[0].url, $(document).slapos('store', 'host')+'/computer/id/supply');
        ok(!callback.calledOnce, "callback should not be called");
    });
    
    test("Bang computer", function(){
        
        var callback = this.spy();
        this.spy(jQuery, 'ajax');
        
        response = [200, this.header, ''];
        this.server.respondWith("POST", /\/computer\/(\w+)\/bang/, response);
        
        data = '';
        $(document).slapos('bangComputer', 'id', data, callback);
        this.server.respond();
        
        equal(jQuery.ajax.getCall(0).args[0].url, $(document).slapos('store', 'host')+'/computer/id/bang');
        ok(callback.calledOnce, "callback should be called");
    });

    test("Bang computer - Fail", function(){
        
        var callback = this.spy();
        this.spy(jQuery, 'ajax');
        
        this.server.respondWith("POST", /\/computer\/(\w+)\/bang/, this.error);
        
        $(document).slapos('bangComputer', 'id', '', callback);
        this.server.respond();
        
        equal(jQuery.ajax.getCall(0).args[0].url, $(document).slapos('store', 'host')+'/computer/id/bang');
        ok(!callback.calledOnce, "callback should not be called");
    });
    
    test("Report computer usage", function(){
        
        var callback = this.spy();
        this.spy(jQuery, 'ajax');
        
        response = [200, this.header, ''];
        this.server.respondWith("POST", /\/computer\/(\w+)\/report/, response);
        
        data = '';
        $(document).slapos('computerReport', 'id', data, callback);
        this.server.respond();
        
        equal(jQuery.ajax.getCall(0).args[0].url, $(document).slapos('store', 'host')+'/computer/id/report');
        ok(callback.calledOnce, "callback call");
    });
    
    test("Report computer usage - Fail", function(){
        
        var callback = this.spy();
        this.spy(jQuery, 'ajax');
        
        this.server.respondWith("POST", /\/computer\/(\w+)\/report/, this.error);
        
        $(document).slapos('computerReport', 'id', '', callback);
        this.server.respond();
        
        equal(jQuery.ajax.getCall(0).args[0].url, $(document).slapos('store', 'host')+'/computer/id/report');
        ok(!callback.calledOnce, "callback should not be called");
    });
    
    module("Common Tests");
    
    test("Check if host has been saved", function(){
        $(document).slapos({host: "http://foo.com"});
        equal($(document).slapos('store', 'host'), "http://foo.com", "should contains host whatever is the method")
    });
    
    test("Modifying host after initialisation at start", function(){
        $(document).slapos('store', 'host', 'http://examples.com');
        equal($(document).slapos('store', 'host'), "http://examples.com", "should contains modified host")
    });
});
