// pipeline {
//     agent any
//     environment {
//         GIT_CREDENTIALS_ID = 'github-credentials-id'
//         GC_KEY = 'gke-credentials-id'
//         REGISTRY_URI = 'asia-south1-docker.pkg.dev'
//         PROJECT_ID = 'reflection01-431417'
//         ARTIFACT_REGISTRY = 'reflection-artifacts'
//         CLUSTER = 'reflection-cluster-1'
//         ZONE = 'us-central1'  // Ensure this matches the zone where your cluster is located
//         REPO_URL = "${REGISTRY_URI}/${PROJECT_ID}/${ARTIFACT_REGISTRY}"
//     }
//     stages {
//         stage('Checkout') {
//             steps {
//                 git url: 'https://github.com/BorisSolomonia/authentication-server.git', branch: 'master', credentialsId: "${GIT_CREDENTIALS_ID}"
//             }
//         }
//         stage('Build and Push Image') {
//             steps {
//                 withCredentials([file(credentialsId: "${GC_KEY}", variable: 'GC_KEY_FILE')]) {
//                     script {
//                         withEnv(["GOOGLE_APPLICATION_CREDENTIALS=${GC_KEY_FILE}"]) {
//                             sh "gcloud auth activate-service-account --key-file=${GC_KEY_FILE} --verbosity=info"
//                             sh 'gcloud auth configure-docker'
//                         }
//                         def mvnHome = tool name: 'maven', type: 'maven'
//                         def mvnCMD = "${mvnHome}/bin/mvn"
//                         sh "${mvnCMD} clean install jib:build -DREPO_URL=${REPO_URL} -X"
//                     }
//                 }
//             }
//         }
//         stage('Deploy') {
//             steps {
//                 script {
//                     sh "sed -i 's|IMAGE_URL|${REPO_URL}|g' authentication-server-deployment.yaml"
//                     withCredentials([file(credentialsId: "${GC_KEY}", variable: 'GC_KEY_FILE')]) {
//                         step([
//                             $class: 'KubernetesEngineBuilder',
//                             projectId: env.PROJECT_ID,
//                             cluster: "${env.CLUSTER} (${env.ZONE})", // Ensure this is correct
//                             location: env.ZONE,
//                             manifestPattern: 'authentication-server-deployment.yaml',
//                             credentialsId: "${PROJECT_ID}",
//                             verifyDeployments: true
//                         ])
//                     }
//                 }
//             }
//         }

//     }
// }

// აქ სპეციალურად არის დატოვებული ძველი კოდიც რომ ჩანდეს რა არის სხვაობა ამ ორს შორის. მეორე არის სწორი.
// pipeline {
//     agent any
//     environment {
//         GIT_CREDENTIALS_ID = 'github-credentials-id'
//         GC_KEY = 'gke-credentials-id'
//         REGISTRY_URI = 'asia-south1-docker.pkg.dev'
//         PROJECT_ID = 'reflection01-431417'
//         ARTIFACT_REGISTRY = 'reflection-artifacts'
//         IMAGE_NAME = 'authentication-server'
//         CLUSTER = 'reflection-cluster-1'
//         ZONE = 'us-central1'  // Ensure this matches the zone where your cluster is located
//         AUTH_SERVER = 'http://34.121.119.90:8080'
//         AUTH_SERVER_JWKS = 'http://34.121.119.90:8080/oauth2/jwks'
//     }
//     stages {
//         stage('Checkout') {
//             steps {
//                 git url: 'https://github.com/BorisSolomonia/authentication-server.git', branch: 'master', credentialsId: "${GIT_CREDENTIALS_ID}"
//             }
//         }
//         stage('Build and Push Image') {
//             steps {
//                 withCredentials([file(credentialsId: "${GC_KEY}", variable: 'GC_KEY_FILE')]) {
//                     script {
//                         withEnv(["GOOGLE_APPLICATION_CREDENTIALS=${GC_KEY_FILE}"]) {
//                             sh "gcloud auth activate-service-account --key-file=${GC_KEY_FILE} --verbosity=info"
//                             sh "gcloud auth configure-docker ${REGISTRY_URI}"
//                         }
//                         def mvnHome = tool name: 'maven', type: 'maven'
//                         def mvnCMD = "${mvnHome}/bin/mvn"
//                         def imageTag = "v${env.BUILD_NUMBER}"
//                         def imageFullName = "${REGISTRY_URI}/${PROJECT_ID}/${ARTIFACT_REGISTRY}/${IMAGE_NAME}:${imageTag}"
                        
//                         // Build and push Docker image using Jib
//                         sh "${mvnCMD} clean compile package"
//                         sh "${mvnCMD} com.google.cloud.tools:jib-maven-plugin:3.4.3:build -Dimage=${imageFullName}"

//                         // Update deployment manifest with new image
//                         sh "sed -i 's|IMAGE_URL|${imageFullName}|g' authentication-server-deployment.yaml"
//                     }
//                 }
//             }
//         }
//         stage('Deploy') {
//             steps {
//                 withCredentials([file(credentialsId: "${GC_KEY}", variable: 'GC_KEY_FILE')]) {
//                     script {
//                         sh "gcloud auth activate-service-account --key-file=${GC_KEY_FILE} --verbosity=info"
//                         sh "gcloud container clusters get-credentials ${CLUSTER} --zone ${ZONE} --project ${PROJECT_ID}"
//                         sh "kubectl apply -f authentication-server-deployment.yaml"
//                     }
//                 }
//             }
//         }
//     }
// }

pipeline {
    agent any
    environment {
        GIT_CREDENTIALS_ID = 'github-credentials-id'  // Change to your actual credentials ID
        GC_KEY = 'gke-credentials-id'  // Change to your actual Google Cloud credentials ID
        REGISTRY_URI = 'us-east4-docker.pkg.dev'
        PROJECT_ID = 'brooks-437520'
        ARTIFACT_REGISTRY = 'brooks-artifacts'
        IMAGE_NAME = 'authentication-server'  // Update with the correct image name
        CLUSTER = 'low-cost-cluster'
        ZONE = 'us-central1-a'
        JAVA_HOME = '/usr/lib/jvm/java-17-openjdk-amd64' // Set JAVA_HOME for WSL
        PATH = "${JAVA_HOME}/bin:${env.PATH}" // Add JAVA_HOME to the PATH for WSL
    }
    stages {
        stage('Checkout') {
            steps {
                git url: 'https://github.com/BorisSolomonia/authentication-server.git', branch: 'master', credentialsId: "${GIT_CREDENTIALS_ID}"
            }
        }
        stage('Build and Push Image') {
            steps {
                withCredentials([file(credentialsId: GC_KEY, variable: 'GC_KEY_FILE')]) {
                    script {
                        // Translate the key file path to be compatible with WSL
                        def wslKeyFilePath = GC_KEY_FILE.replace('\\', '/').replace('C:', '/mnt/c')

                        withEnv(["GOOGLE_APPLICATION_CREDENTIALS=${wslKeyFilePath}"]) {
                            // Authenticate with Google Cloud using WSL
                            bat "wsl -d Ubuntu-22.04 gcloud auth activate-service-account --key-file=${wslKeyFilePath} --verbosity=debug"
                            bat "wsl -d Ubuntu-22.04 gcloud auth configure-docker ${REGISTRY_URI}"
                        }

                        // Maven command for WSL environment
                        def mvnCMD = "/home/borissolomonia/maven/bin/mvn"

                        def imageTag = "v${env.BUILD_NUMBER}"
                        def imageFullName = "${REGISTRY_URI}/${PROJECT_ID}/${ARTIFACT_REGISTRY}/${IMAGE_NAME}:${imageTag}"

                        // Build and push Docker image using Jib
                        bat "wsl -d Ubuntu-22.04 ${mvnCMD} clean compile package"
                        bat "wsl -d Ubuntu-22.04 ${mvnCMD} com.google.cloud.tools:jib-maven-plugin:3.4.3:build -Dimage=${imageFullName}"

                        // Update deployment manifest with new image
                        bat "wsl -d Ubuntu-22.04 sed -i \"s|IMAGE_URL|${imageFullName}|g\" authentication-server-deployment.yaml"
                    }
                }
            }
        }
        stage('Deploy') {
            steps {
                withCredentials([file(credentialsId: GC_KEY, variable: 'GC_KEY_FILE')]) {
                    script {
                        // Translate the key file path to be compatible with WSL
                        def wslKeyFilePath = GC_KEY_FILE.replace('\\', '/').replace('C:', '/mnt/c')

                        // Authenticate and deploy to GKE using WSL
                        bat "wsl -d Ubuntu-22.04 gcloud auth activate-service-account --key-file=${wslKeyFilePath} --verbosity=debug"
                        bat "wsl -d Ubuntu-22.04 gcloud container clusters get-credentials ${CLUSTER} --zone ${ZONE} --project ${PROJECT_ID}"
                        bat "wsl -d Ubuntu-22.04 kubectl apply -f authentication-server-deployment.yaml"
                    }
                }
            }
        }
        stage('Debug Maven Path') {
            steps {
                bat "echo Converted Maven Path: /home/borissolomonia/maven/bin/mvn"
            }
        }
    }
}
