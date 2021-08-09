import LocalServer from '../src/localServer/localServer'

export const startSeguroGateway = () => {
    const port = parseInt( process.argv[2] ) || 3001
    const path = process.argv[3] || ''
    new LocalServer ( port, path )
}

