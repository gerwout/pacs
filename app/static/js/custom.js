function switch_add_to_edit() {
    $("#span_add_button").hide();
    $("#computer_form_edit_span").show();
    $("#computer_form_switch_span").show();
    $("#computer_form_switch_span").on('click', function(e) {
        e.preventDefault();
        $("#computer_id").val("");
        $("#computer_form_edit_span").hide();
        $("#computer_form_switch_span").off('click');
        $("#computer_form_switch_span").hide();
        $("#span_add_button").show();
    })
}

document.addEventListener('DOMContentLoaded', function () {
    $("#computer_form_submit").attr("disabled", false);

    $("#computer_form").submit(function() {
        $("#computer_form_submit").attr("disabled", true);
    });

    $("#pacs_status_button").click(function(e) {
        e.stopPropagation();
        e.preventDefault();
        var value = $(this).val();

        if (value == "Enable PACS") {
            var result = confirm("Are you certain you want to enable the PACS compliance check?");
        } else {
            var result = confirm("Are you certain you want to fully disable the PACS compliance check? All connecting devices will be considered compliant!");
        }

        if (result) {
        $(this).attr("disabled", true);
            var current_csrf_token = $("#csrf_token").val();
            var url = "/disable_or_enable_pacs"
            $.ajax({ type: "POST", url: url,  data: {csrf_token: current_csrf_token}, success: function(data) {
                $("#sccm_import_button").attr("disabled", false);
                var json = $.parseJSON(data);
                $("#csrf_token").val(json.csrf_token)
                alert(json.message);
                document.location.href="/";
            }, dataType: "text"});
        }
    });

    $("#sccm_import_button").click(function(e) {
        e.stopPropagation();
        e.preventDefault();
        var result = confirm("Are you certain you want to do a full SCCM import? This will take a while to complete.")
        if (result) {
            $(this).attr("disabled", true);
            var current_csrf_token = $("#csrf_token").val();
            var url = "/sccm_import"
            $.ajax({ type: "POST", url: url,  data: {csrf_token: current_csrf_token}, success: function(data) {
                $("#sccm_import_button").attr("disabled", false);
                var json = $.parseJSON(data);
                $("#csrf_token").val(json.csrf_token)
                alert(json.message);
                document.location.href="/";
            }, dataType: "text"});
        }
    });

    $("#add_mac_icon").click(function(e) {
        e.preventDefault();
        var inputDiv = $("#add_mac_icon").prev().prev().parent();
        var currentCount = $(".mac_address").length;
        var labelHTML = "<label for=\"mac" + (currentCount + 1) + "\">MAC address</label>";
        var inputHTML = "<input class=\"upper mac_address\" id=\"mac" + (currentCount + 1) + "\" name=\"mac\" type=\"text\">";
        var totalHTML = "<div class=\"input-field\">" + labelHTML + inputHTML + "</div>";
        $(totalHTML).insertAfter($("#add_mac_icon").prev());
    });

    $(".delete_computer_icon").click(function(e) {
        e.stopPropagation();
        e.preventDefault();
        var result = confirm("Delete record?")
        if (result) {
            var current_csrf_token = $("#csrf_token").val();
            var id = $(this).attr('data-id')
            var url = "/delete/" + id

            $.ajax({ type: "POST", url: url,  data: {csrf_token: current_csrf_token}, success: function(data) {
                var json = $.parseJSON(data);
                if (json.success) {
                    document.location.href="/";
                } else {
                    alert("Could not delete! " + json.errors)
                }
             }, dataType: "text"});
        }
    });

        $("#computer_table th").click(function() {
            var th_value = $(this).text();
            var cur_order_by = $('#order_by').val();
            var cur_asc_or_desc = $('#asc_or_desc').val();
            switch(th_value) {
                case "Name":
                    var order_by = "name";
                    break;
                case "Description":
                    var order_by = "description";
                    break;
                case "Last logon":
                    var order_by = "last_logon_name";
                    break;
                case "Ignore AV":
                    var order_by = "ignore_av_check"
                    break;
                case "Source":
                    var order_by = "source_id"
                    break;
                case "Device ID":
                    var order_by = "device_id"
                    break;
                default:
                    return False;
                    break;
           }
           if (order_by == cur_order_by) {
               if (cur_asc_or_desc == "asc") {
                   cur_asc_or_desc = "desc";
               } else {
                   cur_asc_or_desc = "asc";
               }
           } else {
               cur_asc_or_desc = "asc";
           }
           var url = "/index/" + order_by + "/" + cur_asc_or_desc
           document.location.href=url;
        });

    $("#computer_table tr").click(function() {
        var id = $(this).find("td:last-child a").data("id");
        var name = $.trim($(this).find("td").eq(0).text());
        var description = $.trim($(this).find("td").eq(1).text());
        var device_id = $.trim($(this).find("td").eq(5).text());
        var ignore_av_check = $.trim($(this).find("td").eq(3).text());
        var mac_addresses = $.trim($(this).find("td").eq(4).text()).split(" ");
        if (mac_addresses == "None") {
            mac_addresses = "";
        }
        if (device_id == "None") {
            device_id = "";
        }
        $("#computer_id").val(id);
        $("#name").focus();
        $("#name").val(name);
        $("#description").focus();
        $("#description").val(description);
        $("#device_id").focus();
        $("#device_id").val(device_id)
        $("#ignore_av_check").prop('checked', ignore_av_check == "True");

        var current_mac_field_count = $(".mac_address").length;
        var current_mac_count = mac_addresses.length;

        // more inputs
        if (current_mac_field_count > current_mac_count) {
            var diff = current_mac_field_count - current_mac_count;
            for (var i = diff; i > 0; i--) {
                var id = "#mac" + (i + 1);
                $(id).parent().remove();
            }
        } else if(current_mac_field_count < current_mac_count) {
            var diff = current_mac_count - current_mac_field_count;
            for (i = 0; i < diff; i++) {
                $("#add_mac_icon").trigger("click");
            }
        }
        for (i = 0; i < current_mac_count; i++) {
            var id = "#mac" + (i + 1)
            $(id).focus();
            $(id).val(mac_addresses[i])
        }
        switch_add_to_edit();
    });
});



