import express, { Express, Request, Response } from 'express';


export const app: Express = express();
const port = 8080;

app.get('/', (req: Request, res: Response) => {
    res.send("Basic Express Setup");
})

app.listen(port, () => {
    console.log(`Server ready on port ${port}`);
})