// Hebrides Cyber security scan for Jenkins (declarative pipeline).
//
// 1. Save https://www.hebridescyber.co.uk/ci/hebrides-scan.sh in your repository
//    as ci/hebrides-scan.sh. The agent needs sh, curl and jq.
// 2. Manage Jenkins -> Credentials: add a "Secret text" credential with the
//    id hebrides-cyber-api-key holding your API key.
// 3. Set HEBRIDES_TARGET_URL below to a site you have verified.
//
// Fails only on new findings at or above HEBRIDES_FAIL_ON that you have not
// triaged. New findings also appear in the build's test results.

pipeline {
  agent any

  environment {
    HEBRIDES_CYBER_API_KEY = credentials('hebrides-cyber-api-key')
    HEBRIDES_TARGET_URL    = 'https://staging.example.com'
    HEBRIDES_FAIL_ON       = 'high'
    HEBRIDES_JUNIT_FILE    = 'hebrides-junit.xml'
  }

  triggers {
    cron('H 3 * * 1') // weekly, as well as on every build
  }

  stages {
    stage('Security scan') {
      steps {
        sh 'sh ci/hebrides-scan.sh'
      }
    }
  }

  post {
    always {
      junit allowEmptyResults: true, testResults: 'hebrides-junit.xml'
      archiveArtifacts artifacts: 'hebrides-scan.json', allowEmptyArchive: true
    }
  }
}
