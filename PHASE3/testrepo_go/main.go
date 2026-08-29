// Fixture Go INTENTIONNELLEMENT vulnérable — testrepo_go.
// Chaque vulnérabilité est attendue par ATTENDUS.yaml (référentiel généré depuis
// une exécution réelle de gosec). Clé AWS = exemple de la documentation AWS
// (fausse, publiée par AWS elle-même). Ne rien « corriger » ici.
package main

import (
	"crypto/md5"
	"crypto/tls"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"os"
)

const password = "SuperSecret123!"          // G101 attendu

var apiKey = "AKIAIOSFODNN7EXAMPLE"         // G101 + gitleaks attendus (fausse clé doc AWS)

func hashPassword(p string) string {
	h := md5.Sum([]byte(p)) // G401/G501 attendu : MD5 cassé
	return fmt.Sprintf("%x", h)
}

func lookupUser(db *sql.DB, name string) (*sql.Row, error) {
	// G201 attendu : injection SQL par concaténation
	return db.QueryRow(fmt.Sprintf("SELECT id FROM users WHERE name='%s'", name)), nil
}

func fetchInsecure(url string) ([]byte, error) {
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // G402 attendu
	}}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func readUserFile(path string) ([]byte, error) {
	f, err := os.Open(path) // G304 attendu : inclusion de fichier par variable
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

func main() {
	fmt.Println(hashPassword(password), apiKey)
}

// Jeton de fixture : FAUX jeton GitHub (même valeur factice documentée que
// testrepo/app.py). Détecté par gitleaks — c'est l'occasion de convergence
// gitleaks/semgrep sur le même fichier, mesurée par le chantier largeur-Go.
var githubToken = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"
