function send(data) {
	try {
		ws.send(data);
	} catch (e) {
        void(0);
	}
}

function log(msg) {
	send(msg === undefined ? 'undefined' : msg.toString());
	document.getElementById("log").innerHTML += ""+msg+"</br>";
}