#!/usr/bin/env bash

################################################################################
################################################################################
########### Super-Linter linting Functions #####################################
################################################################################
################################################################################
########################## FUNCTION CALLS BELOW ################################
################################################################################
################################################################################
#### Function SetupSshAgent ####################################################
function SetupSshAgent() {
  # Check to see if a SSH_KEY_SECRET was passed
  if [ -n "${SSH_KEY}" ]; then
    info "--------------------------------------------"
    info "SSH key found, setting up agent..."
    export SSH_AUTH_SOCK=/tmp/ssh_agent.sock
    ssh-agent -a "${SSH_AUTH_SOCK}" >/dev/null
    ssh-add - <<<"${SSH_KEY}" 2>/dev/null
  fi
}
################################################################################
#### Function SetupGithubComSshKeys ############################################
function SetupGithubComSshKeys() {
  if [[ -n "${SSH_KEY}" || "${SSH_SETUP_GITHUB}" == "true" ]]; then
    info "Adding github.com SSH keys"
    # Fetched out of band from
    # https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints
    GITHUB_RSA_FINGERPRINT="SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s"
    GITHUB_ECDSA_FINGERPRINT="SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM"
    GITHUB_ED25519_FINGERPRINT="SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU"
    ssh-keyscan -t rsa github.com >/tmp/github_rsa.pub 2>/dev/null
    ssh-keyscan -t ecdsa github.com >/tmp/github_ecdsa.pub 2>/dev/null
    ssh-keyscan -t ed25519 github.com >/tmp/github_ed25519.pub 2>/dev/null
    if [[ "${SSH_INSECURE_NO_VERIFY_GITHUB_KEY}" == "true" ]]; then
      warn "Skipping github.com key verification and adding without checking fingerprint"
      mkdir -p ~/.ssh
      cat /tmp/github_{rsa,ecdsa,ed25519}.pub >>~/.ssh/known_hosts
    else
      mkdir -p ~/.ssh
      if [[ "$(ssh-keygen -lf /tmp/github_rsa.pub)" == "3072 ${GITHUB_RSA_FINGERPRINT} github.com (RSA)" ]]; then
        info "Successfully verified github.com RSA key"
        cat /tmp/github_rsa.pub >>~/.ssh/known_hosts
      fi
      if [[ "$(ssh-keygen -lf /tmp/github_ecdsa.pub)" == "256 ${GITHUB_ECDSA_FINGERPRINT} github.com (ECDSA)" ]]; then
        info "Successfully verified github.com ECDSA key"
        cat /tmp/github_ecdsa.pub >>~/.ssh/known_hosts
      fi
      if [[ "$(ssh-keygen -lf /tmp/github_ed25519.pub)" == "256 ${GITHUB_ED25519_FINGERPRINT} github.com (ED25519)" ]]; then
        info "Successfully verified github.com Ed25519 key"
        cat /tmp/github_ed25519.pub >>~/.ssh/known_hosts
      fi
      if [ ! -f "${HOME}/.ssh/known_hosts" ]; then
        error "Could not verify any github.com key. SSH requests to github.com will likely fail."
      fi
    fi
  fi
}
################################################################################
