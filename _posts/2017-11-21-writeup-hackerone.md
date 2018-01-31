---
title:  "Write-Up Hackerone"
header:
  teaser: "https://farm5.staticflickr.com/4076/4940499208_b79b77fb0a_z.jpg"
categories: 
  - ES
tags:
  - ES
  - CTF
  - HackerOne
author: Borja Martinez
---

Vamos a estrenar el blog con una divertida entrada (que esperemos sean muchas) con la resolución de una de las cosas que más nos gustan en el departamento: los retos de seguridad o CTF.

Hace poco se ha realizado el CTF de HackerOne H1-212 que se puede encontrar en <https://www.hackerone.com/blog/hack-your-way-to-nyc-this-december-for-h1-212>.
Y hoy os traemos este Write-Up de la mano de uno de nuestros compañeros Borja Martínez, donde nos explica cómo resolvió la prueba de H1, relacionada con una vulnerabilidad de SSRF.


Para empezar, accedemos a la dirección que proporcionan en el enunciado ([http://104.236.20.43](http://104.236.20.43/)) y nos encontramos con la página por defecto de un Apache2.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2017-11-21-writeup-hackerone/w_html_3f4c94537b6d7294.png)

Después de unas breves pruebas nos encontramos con el directorio /flag
donde sale un simple mensaje (You really thought it would be that easy?
Keep digging!).

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2017-11-21-writeup-hackerone/w_html_55541141253cb6d8.png)

Volviendo al enunciado
(https://www.hackerone.com/blog/hack-your-way-to-nyc-this-december-for-h1-212)
nos damos cuenta que se se hace referencia a un panel de administración
para la organizacion de “acme.org”:

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2017-11-21-writeup-hackerone/w_html_9a79b1de57dc777a.png)


Con lo cual intuimos que el servidor puede presentar varios virtual
hosts, por lo que se realizan varias pruebas en la cabecera hasta dar
con el host correcto.

host: admin.acme.org


![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2017-11-21-writeup-hackerone/w_html_21cf7e660923a149.png)

Al realizar la petición nos percatamos que en la respuesta se fija el
valor de una cookie (admin=no). Nuestro instinto más primario nos llevar
a cambiar ese valor a “yes”.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2017-11-21-writeup-hackerone/w_html_f521a117e19f533f.png)

Tampoco iba a ser tan fácil y seguimos poco a poco con las pruebas. En
este punto apreciamos que no acepta el método GET ya que nos da un error
405 por lo que lo cambiamos por el otro método más utilizado “POST”.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2017-11-21-writeup-hackerone/w_html_96e7e60775cde172.png)

Ahora obtenemos el error 406. Después de fuzzear durante un rato
ficheros encontramos read.php que nos devuelve en la respuesta un error
diferente. Hemos avanzamos hasta el error 418, junto a lo que parece ser
una respuesta a una query de json

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2017-11-21-writeup-hackerone/w_html_1e9f594fab4a83f5.png)

A partir del error que ha devuelto el servidor, formamos una petición
json con el valor que espera”row”. Ahora nos pide el valor “domain”.


![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2017-11-21-writeup-hackerone/w_html_3ced3473f89bfa92.png)

Volvemos a formar la petición json con el valor domain y vemos que nos
faltan valores que vamos añadiendo.

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2017-11-21-writeup-hackerone/w_html_da91554b677298f1.png)


Llegamos a formar la peticion 212.dominio.com que nos devuelve el
siguiente directorio:


![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2017-11-21-writeup-hackerone/w_html_cbd9b3efd576c082.png)

Vemos que nos devuelve un campo data vacío, y a cada petición que
hacemos con un nuevo dominio nos crea un id nuevo id=0,id=1,id=2…

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2017-11-21-writeup-hackerone/w_html_b15c4ea3a8d34445.png)

Si en el dominio ponemos un dominio válido vemos que nos resuelve el
contenido del mismo en base64, para hacer la prueba usamos el dominio
borjmz.com que apunta a 127.0.0.1

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2017-11-21-writeup-hackerone/w_html_490107939591b325.png)

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2017-11-21-writeup-hackerone/w_html_40654c2951a78258.png)


Nos devuelve la página de inicio de Apache con lo cual imaginamos que
podríamos estar ante un SSRF. Nos disponemos a escanear y encontramos un
servidor nginx en el puerto 1337

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2017-11-21-writeup-hackerone/w_html_ef5135a7c198081a.png)

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2017-11-21-writeup-hackerone/w_html_520593c0111bb97e.png)

Descodificamos el base64 y nos encontramos con la siguiente frase:

- Hmm, where would it be?

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2017-11-21-writeup-hackerone/w_html_459b46b840b8b3d3.png)

Parece que vamos por buen camino....

Nos da a entender que puede estar en el archivo /flag pero no podemos
leer el directorio ya que tenemos el problema que la petición incluye un
.com con lo cual al realizar la petición queda de la siguiente manera
212.borjmz.com:1337/flag.com (127.0.0.1:1337/flag.com) con lo cual
necesitamos realizar un bypass del .com


Probamos con varios caracteres pero están prohibidos:

![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2017-11-21-writeup-hackerone/w_html_6af6b66e6f348f68.png)


Se hacen varias pruebas para lograr el bypass


![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2017-11-21-writeup-hackerone/w_html_ee674661b93e1745.png)


![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2017-11-21-writeup-hackerone/w_html_626874a3f89cb614.png)

Finalmente se ha conseguido hacer el bypass con las siguiente petición:

```
[{"domain" :
"212.borjmz.com/flag\\nFake:.com"}]{style="background: #f9f2f4"}
```

Nos llega la respuesta correctamente en base64 y al descifrar obtenemos
la flag.


![alt]({{ site.url }}{{ site.baseurl }}/assets/images/2017-11-21-writeup-hackerone/w_html_f55afe6afc3795da.png)

```JSON
{"data":"RkxBRzogQ0YsMmRzVlwvXWZSQVlRLlRERXBgdyJNKCVtVTtwOSs5RkR7WjQ4WCpKdHR7JXZTKCRnN1xTKTpmJT1QW1lAbmthPTx0cWhuRjxhcT1LNTpCQ0BTYip7WyV6IitAeVBiL25mRm5hPGUkaHZ7cDhyMlt2TU1GNTJ5OnovRGg7ezYK"}
```

FLAG:
```
CF,2dsV\\/\]fRAYQ.TDEp\`w"M(%mU;p9+9FD{Z48X\*Jtt\{\%vS(\$g7\\S):f%=P\[Y@nka=&lt;tqhnF&lt;aq=K5:BC@Sb\*{\[%z"+@yPb/nfFna&lt;e\$hv{p8r2\[vMMF52y:z/Dh;{6
```

Gracias por el reto!
