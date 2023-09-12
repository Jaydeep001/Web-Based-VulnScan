from turtle import width
from flask import Flask,render_template, request
import subprocess

app = Flask(__name__)

@app.route("/",methods=['POST'])
def search_url():
    url= request.form["search"]
    with open("output.txt","w") as file:
        
        file.write(url)
        
    subprocess.call(["./jaydeep.sh"], shell=True)
        
    return "Processing///+++"
        