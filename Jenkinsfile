pipeline {
    agent any
    environment {
        APP = 'ev3-app'
        NET = 'ev3-net'
    }
    stages {
        stage('1. Clonar codigo') {
            steps {
                checkout scm
                sh 'git log --oneline -3'
            }
        }
        stage('2. Construir imagen') {
            steps {
                sh 'docker build -t ${APP}:${BUILD_NUMBER} -t ${APP}:latest .'
            }
        }
        stage('3. Pruebas') {
            steps {
                sh '''
                    docker rm -f ev3-test || true
                    docker run -d --name ev3-test --network ${NET} ${APP}:latest
                    sleep 6
                    curl -s -o /dev/null -w "HTTP %{http_code}\\n" http://ev3-test:5000/login | tee resultado.txt
                    grep -q "HTTP 200" resultado.txt
                '''
            }
        }
        stage('4. Desplegar') {
            steps {
                sh '''
                    docker rm -f ev3-app || true
                    docker run -d --name ev3-app --network ${NET} -p 5000:5000 --restart unless-stopped ${APP}:latest
                    docker ps --filter name=ev3-app
                '''
            }
        }
    }
    post {
        always { sh 'docker rm -f ev3-test || true' }
        success { echo 'Pipeline completado: la app quedo desplegada en el puerto 5000.' }
        failure { echo 'El pipeline fallo: revisar la etapa marcada en rojo.' }
    }
}
