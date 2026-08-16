<center>
	<h1 align="center">BlockTheSpot</h1> 
	<h4 align="center">A multi-purpose adblocker and skip-bypass for the <strong>Spotify for Windows (64 bit)</strong> </h4>
    <h5 align="center">Please support Spotify by purchasing premium</h5>
    <p align="center">
        <strong>Last updated:</strong> 12 February 2026<br>
        <strong>Last tested version:</strong> see `config.ini`
    </p> 
</center>

### Virus warning on windows defender issue:
* The code is on Github, everyone can check it.
* false positive can happen. but don't trust me on this, try verify by compile your own BTS and compare with the release.

### Features:
* Focus mainly on block listening ads and performance, cosmetic aren't main purpose.

#### Experimental features from developer mode
- Click on the 2 dots in the top left corner of Spotify > Develop > Show debug window. Play around with the options.
- Enable/disable feature by yourself in realtime and on demand.

:warning: This mod is for the [**Desktop Application**](https://www.spotify.com/download/windows/) of Spotify on Windows only and **not the Microsoft Store version**.

#### Fresh installation
1. Browse to your Spotify installation folder `%APPDATA%\Spotify`
2. Rename `chrome_elf.dll` to `chrome_elf_required.dll`
4. Download `chrome_elf.dll` and `blockthespot.dll`from releases
5. Put downloaded file from 4 to Spotify directory. 
6. Download latest config.ini from github to Spotify directory (in the release)

#### Update from spotify
1. Be sure spotify is working correctly without any patch (the best solution is to reinstall spotify), if spotify is working you can go to step 2.
2. Browse to your Spotify installation folder `%APPDATA%\Spotify`
4. Rename `chrome_elf.dll` to `chrome_elf_required.dll`
5. Download `chrome_elf.dll` and `blockthespot.dll`from releases
6. Put downloaded file from 4 to Spotify directory. 
7. Download latest config.ini from github to Spotify directory (in the release)

### Uninstall:
1. Remove `chrome_elf.dll`, `blockthespot.dll` and `config.ini` from Spotify directory.
2. Rename `chrome_elf_required.dll` to `chrome_elf.dll`

or just reinstall Spotify

### Additional Notes:

* For more support https://github.com/thomas-quant/BlockTheSpot-Resilient or https://github.com/mrpond/blockthespot.





