import axios from 'axios'

const API = 'http://localhost:8000/api'

// Inicia um scan em um repositório
export const iniciarScan = (repoUrl: string) =>
  axios.post(`${API}/scan?repo_url=${encodeURIComponent(repoUrl)}`)

// Busca todos os findings salvos
export const buscarFindings = () =>
  axios.get(`${API}/findings`).then(r => r.data)

// Busca o resumo geral
export const buscarResumo = () =>
  axios.get(`${API}/resumo`).then(r => r.data)

// Limpa todos os findings
export const limparFindings = () =>
  axios.delete(`${API}/findings`)