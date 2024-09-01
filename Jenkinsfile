// 
pipeline {
    agent any
    environment {
        GIT_CREDENTIALS_ID = 'github-credentials-id'
        GC_KEY = 'gke-credentials-id'
        REGISTRY_URI = 'asia-south1-docker.pkg.dev'
        PROJECT_ID = 'reflection01-431417'
        ARTIFACT_REGISTRY = 'reflection-artifacts'
        CLUSTER = 'reflection-cluster-1'
        ZONE = 'us-central1'
        REPO_URL = "${REGISTRY_URI}/${PROJECT_ID}/${ARTIFACT_REGISTRY}"
    }
    stages {
        stage('Checkout') {
            steps {
                git url: 'https://github.com/BorisSolomonia/authentication-server.git', branch: 'master', credentialsId: "${GIT_CREDENTIALS_ID}"
            }
        }
        stage('Build and Push Image') {
            steps {
                script {
                    def imageTag = "v${env.BUILD_NUMBER}"
                    withCredentials([file(credentialsId: "${GC_KEY}", variable: 'GC_KEY_FILE')]) {
                        withEnv(["GOOGLE_APPLICATION_CREDENTIALS=${GC_KEY_FILE}"]) {
                            sh "gcloud auth activate-service-account --key-file=${GC_KEY_FILE} --verbosity=info"
                            sh 'gcloud auth configure-docker'
                        }
                        def mvnHome = tool name: 'maven', type: 'maven'
                        def mvnCMD = "${mvnHome}/bin/mvn"
                        sh "${mvnCMD} clean install jib:build -DREPO_URL=${REPO_URL}:${imageTag} -X"
                    }
                }
            }
        }
        stage('Deploy') {
            steps {
                script {
                    sh "sed -i 's|IMAGE_URL|${REPO_URL}:${imageTag}|g' authentication-server-deployment.yaml"
                    withCredentials([file(credentialsId: "${GC_KEY}", variable: 'GC_KEY_FILE')]) {
                        step([
                            $class: 'KubernetesEngineBuilder',
                            projectId: env.PROJECT_ID,
                            cluster: "${env.CLUSTER} (${env.ZONE})",
                            location: env.ZONE,
                            manifestPattern: 'authentication-server-deployment.yaml',
                            credentialsId: "${PROJECT_ID}",
                            verifyDeployments: true
                        ])
                    }
                    sh "kubectl rollout restart deployment authentication-server"
                }
            }
        }
    }
}
