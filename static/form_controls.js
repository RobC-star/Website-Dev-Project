function myFunction() {
  const x = document.getElementById("my_password");
  if (x.type === "password") {
    x.type = "text";
  } else {
    x.type = "password";
  }
}

function validateFormUsername() {
  const x = document.getElementById("submitBTN");
  if (x.name === "form_submit_login_btn") {
    x.value = "updating"
  }else{
    x.value = "logging_in"
  }
}
