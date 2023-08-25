const mysql = require('mysql2');
const express = require('express');
const session = require('express-session');
const path = require('path');
const res = require('express/lib/response');
const keypar = require('keypair');
const forge = require('node-forge');
const {PythonShell} = require('python-shell');
const puertos =[4000,4001,4002,4003];
const router = express.Router();
var request = require('request');
var bodyParser = require('body-parser');
var parche1 = ""

function getRandomInt(min, max) {
    min = Math.ceil(min);
    max = Math.floor(max);
    return Math.floor(Math.random() * (max - min) + min); //The maximum is exclusive and the minimum is inclusive
  }

const connection = mysql.createConnection({
	host     : 'localhost',
	user     : 'alumne',
	password : 'alumne',
	database : 'usuaris'
});

const app = express();
app.set("view engine", "ejs");
app.set('views', path.join(__dirname, 'views'));

app.use(session({
	secret: 'secret',
	resave: true,
	saveUninitialized: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'static')));



// http://localhost:3000/
app.get('/', function(request, response) {
	// Render login template
	response.render(__dirname + '/views/login', function(err,html){
		response.send(html);
	})
});

app.get('/menu', function(request, response) {
    //I'm server side
	connection.query('SELECT canVote FROM usuaris WHERE dni= ?', request.session.username, function(error, results, fields) {
		console.log("Username session: " + request.session.username);
		console.log("Username canVote: " + results[0].canVote);
		if (error) throw error;
		if (results.length > 0){
			console.log(__dirname + '/views/menu');
			response.render(__dirname + '/views/menu', {varToPass:results[0].canVote},  function (err, html){
				response.send(html);
				response.end();
			})
		}
		
		
	});
});

function httpGet(theUrl){
    var xmlHttp = new XMLHttpRequest();
    xmlHttp.open( "GET", theUrl, true ); // false for synchronous request
    xmlHttp.send( null );
    return xmlHttp.responseText;
}


app.get('/chain', (req, res) => {
    var puerto=puertos[getRandomInt(0,3)];
    var url = 'http://127.0.0.1:'+puerto+'/chain';
    //response = httpGet(url);
    //console.log(response);

	response = {
		"chain": [
		  {
			"previous_hash": "1",
			"proof": 100,
			"timestamp": 0,
			"transactions": []
		  }
		],
		"length": 1
	  }
	
	res.status(200).send(response); //MIRAR SI ES CORRECTO
});


app.get('/results', (req, res) => {
    var puerto=puertos[getRandomInt(0,4)];
    var url = 'http://127.0.0.1:'+puerto+'/results';
    
	response = httpGet(url);
    console.log(response);
	res.status(200).send(response); //MIRAR SI ES CORRECTO
});



var string_partidos = "";
var votacio = "";
var string_isGenerated = "";

var privateKey;
var publicKey;

app.post('/updateDB',function(request,response){
	publicKey = JSON.parse(JSON.stringify(request.body)).a;
	
	console.log(publicKey);

	const connection3 = mysql.createConnection({
		host     : 'localhost',
		user     : 'alumne',
		password : 'alumne',
		database : votacio
	});

	//INSERTA DENTRO DE SENDERS LA PUBLIC KEY
	connection3.query('INSERT into sendersPK values(?)' , [publicKey], function(error, results, fields) {
	})

	let myArray = string_isGenerated.split(',');
	const index = myArray.indexOf(votacio);
	myArray.splice(index,1);
	
	console.log(myArray);

	string_isGenerated = "";
	for (let i = 0; i < myArray.length; ++i){
		if (myArray[i] != "") string_isGenerated += myArray[i] + ',';
	}

	//S'HA DE DESCOMENTAR
	//MODIFICA EL CAMPO DE LA DB 
	/*connection.query('UPDATE usuaris SET isGenerated = ? where dni = ?', [string_isGenerated, request.session.username], function(error, results, fields) {
	}) */

	response.status(200).send(); 
});

app.post('/isGenerated', function(request, response) {
	
	votacio = JSON.parse(JSON.stringify(request.body)).a;	
	console.log(votacio);


	//BUSCA SI SE HA GENERADO UNA CLAVE PUBLICA O PRIVADA
	connection.query('SELECT isGenerated from usuaris where dni = ?', [request.session.username], function(error, results, fields) {
		var resultado = results[0].isGenerated;
		string_isGenerated = results[0].isGenerated;
		let word = '';
		
		let trobat = false;
		for (let j = 0; j < resultado.length && trobat == false; ++j){
			let letter = resultado.charAt(j);
			if (letter != ','){
				word += letter;
			}
			else {
                word = " "+ word;
				if (word == votacio) trobat = true;
                console.log(word);
                console.log(votacio);
				word = '';
			}
			//console.log(word);
		}
        if(!trobat){
			//NO SE HA GENERADO UNA CLAVE PUBLICA Y ENVIA UN 200
			//s'ha de generar una public key i eliminar de la db
			console.log('encara no sha generat');
			response.status(200).send(); 
		}
		else {
			//ja s'ha generat una public key
			console.log('ha generat una public key');
			response.status(400).send(); 
		}
	})
	
});

app.post('/sign', function(req, res) {

    //whoimvoting = JSON.stringify(req.body.a);
	firma = req.body.a;
	whoimvoting = req.body.b;
	string_firma = "";

	for (var clave in firma){
		if (firma.hasOwnProperty(clave)){
			string_firma += firma[clave] + ',';
		}
	}

	string_firma2 = string_firma.substring(0,string_firma.length - 1);

	console.log("This is public key in /sign" + publicKey);
	console.log("This is whoimvoting in /sign" + whoimvoting);
    console.log("This /sing" + string_firma2)
	
    res.end();
    //response.send(200);

})

//falla aqui
app.get('/partits', function(request, response){
	console.log("votacio " + votacio);
	console.log("string_partidos" + string_partidos);
	
	const connection2 = mysql.createConnection({
		host     : 'localhost',
		user     : 'alumne',
		password : 'alumne',
		database : 'vot2'
	});

	connection2.query('SELECT entidad from recipientsPK' , function(error, results, fields) {
		if (results.length > 0) {
			let resultado = results[0].entidad + ',';

			for (let i = 1; i < results.length; ++i){
				resultado += results[i].entidad + ',';
			}
            console.log(resultado);
			response.render(__dirname + '/views/partidos', { varToPass2: resultado});
		}
	});  
	
});



// http://localhost:3000/auth
app.post('/auth', function(request, response) {
	// Capture the input fields
	let username = request.body.username;
	let password = request.body.password;
	// Ensure the input fields exists and are not empty
	if (username && password) {
		// Execute SQL query that'll select the account from the database based on the specified username and password
		connection.query('SELECT * FROM usuaris WHERE dni = ? AND passwd = ?', [username, password], function(error, results, fields) {
			// If there is an issue with the query, output the error
			if (error) throw error;
			// If the account exists
			if (results.length > 0) {
				// Authenticate the user
				request.session.loggedin = true;
				request.session.username = username;
				// Redirect to home page
				response.redirect('home');
			} else {
				response.send('Incorrect Username and/or Password!');
			}			
			response.end();
		});
	} else {
		response.send('Please enter Username and Password!');
		response.end();
	}
});

// http://localhost:3000/home
app.get('/home', function(request, response) {
	// If the user is loggedin
	if (request.session.loggedin) {
		// Output username
		response.redirect('/menu');
	} else {
		// Not logged in
		response.send('Please login to view this page!');
	}
	response.end();
});

app.listen(3000);
