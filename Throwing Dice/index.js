var randomnum1=Math.floor(Math.random()*6)+1;
var randomdice1="./images/dice"+randomnum1+".png";

var randomnum2=Math.floor(Math.random()*6)+1;
var randomdice2="./images/dice"+randomnum2+".png";

var image1=document.querySelectorAll("img")[0];
image1.setAttribute("src",randomdice1);

var image2=document.querySelectorAll("img")[1];
image2.setAttribute("src",randomdice2);

if(randomdice1>randomdice2){
    document.querySelector("h1").innerText="Player 1 won 🐷";
}
else if(randomdice1<randomdice2){
    document.querySelector("h1").innerText="Player 2 won 🦉";
}
else{
    document.querySelector("h1").innerText="Draw 🦥";
}