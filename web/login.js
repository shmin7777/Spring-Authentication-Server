function login() {
    let email = $('#email').val();
    let password = $('#password').val();

    $.ajax({
        url: "http://localhost:8080/api/auth/login", // 클라이언트가 HTTP 요청을 보낼 서버의 URL 주소
        data: JSON.stringify({
            "email": email,
            "password": password
        }),  // HTTP 요청과 함께 서버로 보낼 데이터
        method: "POST",   // HTTP 요청 메소드(GET, POST 등)
        dataType: "json", // 서버에서 보내줄 데이터의 타입
        contentType: 'application/json; charset=utf-8',
    })
        // HTTP 요청이 성공하면 요청한 데이터가 done() 메소드로 전달됨.
        .done(function (json) {

        })
        // HTTP 요청이 실패하면 오류와 상태에 관한 정보가 fail() 메소드로 전달됨.
        .fail(function (xhr, status, errorThrown) {

        });

}