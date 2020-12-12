module Scanner.Scan where

import Control.Concurrent
import Control.Monad
import Scanner.Nmap
import System.Directory
import System.FilePath
import System.Process
import System.Random
import Control.Parallel

outdir :: FilePath
outdir = "/" </> "var" </> "nmaplog"

-- scans
type ScanArgs = [String]

pingScan :: ScanArgs
pingScan = ["-sn"]

quickTCPScan :: ScanArgs
quickTCPScan = ["-sC", "-sV"]

quickUDPScan :: ScanArgs
quickUDPScan = ["-sU", "-sV"]

normalScan :: ScanArgs
normalScan = []

udpScan :: ScanArgs
udpScan = ["-sU"]

agressiveScan :: ScanArgs
agressiveScan = ["-A"]

fullPort :: ScanArgs
fullPort = ["-p-"]

fullPortAgressive :: ScanArgs
fullPortAgressive = ["-p-", "-A"]

smbScan :: ScanArgs
smbScan = ["-p445", "-vv", "--script=smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse"]

allScans :: [ScanArgs]
allScans = [pingScan, normalScan, agressiveScan, fullPort, smbScan, fullPortAgressive, udpScan]


-- scanning
makeScan :: String -> ScanArgs -> IO ScanResult
makeScan ips args = do
    filePathName <- randFileName "xml"
    let filePath = outdir </> filePathName
    let args' = ["-oX", filePath] ++ args ++ [ips]
    putStrLn $ "Running with: "++(show args')
    out <- readProcess "nmap" args' []
    d <- parse filePath
    -- Why can't I set world writable permissions in Haskell :\
    -- readProcess "chmod" ["+r", filePath] []
    return d


makeScans :: [String] -> [ScanArgs] -> IO ScanResult
makeScans ips args = do
    let fs = fmap makeScan ips
    let scans = concat $ map (\x -> map (\y -> x y) args) fs
    foldM (fmap . (<>)) mempty scans

combineFromDir :: IO ScanResult
combineFromDir = do
    l <- listDirectory outdir
    let files = map (outdir </>) l
    d <- foldr (<>) mempty (map parse files)
    return d

cleanDir :: IO ()
cleanDir = do
    l <- listDirectory outdir
    let files = map (outdir </>) l
    _ <- sequence $ map removeFile files
    return ()

-- utils
randFileName :: String -> IO String
randFileName ext = do
    gen <- newStdGen
    let str = take 10 $ randomRs ('a','z') gen 
    return $ str <.> ext
