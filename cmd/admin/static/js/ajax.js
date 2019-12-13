const swbb = Swal.mixin({
    customClass: {
      confirmButton: 'btn btn-primary mr-1',
      cancelButton: 'btn btn-secondary'
    },
    buttonsStyling: false
  })

actionCall = function (url, method) {
    return $.ajax({
        url : url,
        method: method,
        dataType:'text',
        success : function(data) {
            swbb.fire("Done", data, 'success').then((result) => {
                location.reload(true);
            });
        },
        error : function(request,error)
        {
            swbb.fire(error, request.responseText, 'error')
        }
    });
}

actionAsk = function (url, method) {
    swbb.fire({
        title: 'Are you sure?',
        text: "This action cannot be undone!",
        icon: 'warning',
        showCancelButton: true,
        confirmButtonText: 'Yes',
        cancelButtonText: 'Cancel',
    }).then((result) => {
        if (result.value) {
            actionCall(url, method);
        }
    }) 
}