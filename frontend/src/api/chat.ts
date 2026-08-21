export async function perguntarSobreFindings(
  pergunta: string,
  findings: any[]
): Promise<string> {

  const API = 'http://localhost:8000/api'

  try {
    const response = await fetch(`${API}/chat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        pergunta: pergunta,
        findings: findings.slice(0, 10)
      })
    })

    const data = await response.json()

    if (data.resposta) {
      return data.resposta
    }
    return 'Não foi possível obter uma resposta no momento.'

  } catch (error) {
    return 'Erro ao conectar com o servidor.'
  }
}