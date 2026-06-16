pipeline {
    agent any

    environment {
        PIP_CACHE_DIR = "${WORKSPACE}/.pip-cache"
    }

    options {
        buildDiscarder(logRotator(numToKeepStr: '10'))
        timeout(time: 30, unit: 'MINUTES')
    }

    parameters {
        string(name: 'PYTHON_VERSION', defaultValue: '3.12', description: 'Python version')
        string(name: 'TZ', defaultValue: 'UTC', description: 'Timezone for tests')
    }

    stages {
        stage('Setup') {
            steps {
                sh '''
                    python --version
                    pip install --upgrade pip
                    pip install -e ".[dev]"
                '''
            }
        }

        stage('Lint') {
            parallel {
                stage('Ruff') {
                    steps {
                        sh 'ruff check credential_rotation/ tests/'
                    }
                }
                stage('Ruff Format') {
                    steps {
                        sh 'ruff format --check credential_rotation/ tests/'
                    }
                }
                stage('MyPy') {
                    steps {
                        sh 'mypy credential_rotation/'
                    }
                }
            }
        }

        stage('Test - Multi Timezone') {
            matrix {
                axes {
                    axis {
                        name 'TZ'
                        values 'UTC', 'Asia/Shanghai', 'America/New_York', 'Europe/London', 'Australia/Sydney'
                    }
                    axis {
                        name 'PYTHON_VERSION'
                        values '3.10', '3.12'
                    }
                }
                stages {
                    stage('Test') {
                        agent {
                            docker {
                                image "python:${PYTHON_VERSION}-slim"
                            }
                        }
                        steps {
                            sh """
                                pip install -e ".[dev]"
                                export TZ=\$TZ
                                echo "Running tests with Python ${PYTHON_VERSION}, TZ=\$TZ"
                                pytest tests/ -v --tb=short -m "not remote and not vault_cloud" \\
                                    --junitxml=test-results-\$TZ-py${PYTHON_VERSION}.xml
                            """
                        }
                        post {
                            always {
                                junit 'test-results-*.xml'
                            }
                        }
                    }
                }
            }
        }

        stage('Timezone Drift Tests') {
            matrix {
                axes {
                    axis {
                        name 'TZ'
                        values 'UTC', 'Asia/Shanghai', 'America/New_York'
                    }
                }
                stages {
                    stage('TZ Drift') {
                        steps {
                            sh """
                                export TZ=\$TZ
                                pytest tests/ -v -m "timezone" --junitxml=test-timezone-\$TZ.xml
                            """
                        }
                    }
                }
            }
            post {
                always {
                    junit 'test-timezone-*.xml'
                }
            }
        }

        stage('DST Tests') {
            matrix {
                axes {
                    axis {
                        name 'TZ'
                        values 'America/New_York', 'Europe/London', 'America/Los_Angeles'
                    }
                }
                stages {
                    stage('DST') {
                        steps {
                            sh """
                                export TZ=\$TZ
                                pytest tests/ -v -m "dst" --junitxml=test-dst-\$TZ.xml
                            """
                        }
                    }
                }
            }
            post {
                always {
                    junit 'test-dst-*.xml'
                }
            }
        }

        stage('Leap Year Tests') {
            steps {
                sh 'pytest tests/ -v -m "leap_year" --junitxml=test-leapyear.xml'
            }
            post {
                always {
                    junit 'test-leapyear.xml'
                }
            }
        }

        stage('Pre-commit') {
            steps {
                sh '''
                    pip install pre-commit
                    pre-commit run --all-files
                '''
            }
        }
    }

    post {
        success {
            echo 'Pipeline succeeded!'
        }
        failure {
            echo 'Pipeline failed!'
        }
        always {
            cleanWs()
        }
    }
}
