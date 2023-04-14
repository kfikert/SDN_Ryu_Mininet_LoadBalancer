from flask import Flask, send_file

app = Flask(__name__)

@app.route('/')
def stream_video():
    return send_file('sample_video.mp4', mimetype='video/mp4')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
