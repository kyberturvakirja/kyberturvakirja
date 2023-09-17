# Kyberturvan pelisäännöt

Tämä luku sisältää aakkosellinen listauksen kyberturvan pelisäännöistä,
joilla saat perusasiat kuntoon. Tärkeimpinä nostoina kannattaa laittaa
kuntoon ainakin **päivitykset** ja **salasanat**, ja
harkita **monivaiheista tunnistautumista** tärkeisiin tileihin.

## Antivirus

Antivirus on hyvä ja tarpeellinen työkalu työkoneen turvaamiseksi, mutta
ei vielä varmista tietoturvaa kokonaisuutena. Nykyisin Windowsin mukana
tuleva Defender antaa kotikoneille riittävän suojan haittaohjelmia
vastaan. Antivirus estää tunnettujen haittaohjelmien ja viruksien ajon
koneella, mikä antaa kattavan muttei täydellisen suojan.

Antiviruksen käytön lisäksi on tärkeää olla avaamatta tiedostoja, jotka
eivät ole tulleet luotettavista lähteistä (mukaan lukien luotettavilta
ihmisiltä tulleita outoja tiedostoja, jotka voivat olla haittaohjelmien
lähettämiä).

## Fyysinen turvallisuus

Vaikka fyysinen turvallisuus on tarkalleen ottaen osa yleistä
tietoturvaa, muutama sana siitä on paikallaan myös kyberturvaoppassa.
Fyysinen turvallisuus sisältää paljon muutakin kuin vain lukot ja
avaimet. Erilaisiin fyysisen maailman uhkiin voi varautua monella
tasolla---esimerkiksi varkauden estoon voivat liittyä (sähkö)lukot,
kulunvalvonta, vartiointi ja ohjeistus siitä mitä tavaroita saa ja ei
saa jättää toimistolle valvomatta. Lisäksi varkauteen ja siitä
palautumiseen voidaan varautua mm. salauksella (varkaus ei anna pääsyä
tietoihin) ja varmuuskopiolla (varkaus ei johda työn menetykseen).

Kuten kyberturvassa yleisesti, fyysisessä turvassakin tärkein näkökulma
on riskien pienentäminen: älä jätä sensitiivisiä papereita tai
IT-laitteita sinne tänne, mieti kuinka avoin pääsy on tarpeellinen eri
tiloihin, miten varkauksiin tai pahantahtoisiin toimijoihin varaudutaan,
ja kuinka tarkka turvallisuus tunnistettujen riskien valossa riittää.
Mikäli varkauden todennäköisyys on pieni, tiedot kryptattu ja varkauden
varalle on nopea palautumissuunnitelma, johon kuuluu uusien työkoneiden
ostaminen lähimarketista ja ajantasaisten varmuuskopioiden palautus
parissa tunnissa, tilanne on erittäin hyvä.

## Kalasteluyritykset (phishing)

Sähköpostilinkit ovat vaarallisia. Nykyisin ei enää pysty erottamaan
ulkonäön perusteella väärää sisäänkirjautumissivua oikeasta, joten ellei
osoiteriviä lukiessa ole tarkkana ja huomaa että osoite poikkeaa
perinteisestä, voi pankkitunnukset lähettää suoraan hakkerille, kun
luulee kirjautuvansa pankkipalveluun. Etenkin verkkopankki kannattaa
aina avata kirjoittamalla osoite itse selaimen osoiteriville. Yrityksen
käyttämät palvelut voi kerätä selaimen kirjanmerkkeihin tai johonkin
palveluhakemistoon (esim. intranet), jolloin niihin kirjautuminen on
nopeaa ja turvallista. Jopa Googlen ensimmäiset hakutulokset saattavat
sisältää maksettuja mainoksia, jotka eivät välttämättä ole luotettavia.

Tietoisuutta kalasteluyrityksistä kannattaa jakaa, kun tilanteita tulee
eteen. Esimerkiksi kuvankaappauksen jakaminen yrityksen pikaviestimellä
kertoo kaikille että "taas on kalastusyrityksiä liikkeellä", mikä
toimii samalla muistutuksena olla tarkkana linkkien avaamisessa ja
kouluttaa tunnistamaan outoja viestejä.

Pankkitunnusten lisäksi erilaiset sosiaalisen median tunnukset ja
sähköpostitilit kannattaa suojata hyvin. Identiteettivarkaus voi johtaa
maineen menetykseen, ja yrityksen virallista sähköpostia voidaan käyttää
eteenpäin asiakkaiden tai yrityskumppanien huijaamiseen.

Kalastelua tapahtuu nykyisin myös muilla tavoin, kuten puhelimen
välityksellä. Avulias asiakaspalvelija voi auttaa asiakasta unohtuneen
salasanan kanssa muistamatta tarkistaa soittajan henkilöllisyyttä, ja
antaa uudet tunnukset kenelle tahansa kysyjälle. Viralliselta
näyttävällä laskulla voikin olla väärä tilinumero. Eri tilanteisiin on
hyvä olla ohjeistus siitä, miten viestijän henkilöllisyys todennetaan ja
mitä kautta palveluihin kirjaudutaan sisään.

## Käyttäjätunnukset

Käyttäjätunnusten hallinnassa kannattaa käyttää segmentointia, eli
välttää avaamasta kaikille täyttä pääsyä kaikkiin palveluihin, mikäli se
ei ole tarpeen. Parhaassa tapauksessa jaettuja tunnuksia (kuten
"admin" tai "ylläpito") ei käytetä, vaan jokaisella työntekijällä on
oma tunnus samaan palveluun. Monivaiheinen tunnistautuminen kannattaa
ottaa käyttöön kaikissa kriittisissä palveluissa.

Perusmuotoisen käyttäjätunnuksen (admin, hallinta tai etunimisukunimi),
muuttamisesta on pieni hyöty. Tilien turvaaminen kannattaa tehdä
turvallisilla salasanoilla ja monivaiheisella tunnistautumisella.
Perusmuotoiset salasanat taas ovat suuri tietoturvariski, ja
vakiosalasanat täytyy vaihtaa. Lue myös erillinen osio salasanoista.

## Laitteisto

Tärkein sääntö laitteistojen tietoturvassa on tehdassalasanojen
muuttaminen, mikäli laite on yhteydessä verkkoon. Kaikki tehtaalla
asetetut valmissalasanat löytyvät internetistä, ja valmiiksi tiedossa
oleva salasana on kuin punainen matto hakkerille. Normaalisti
tehdassalasanat ovat lisäksi erittäin yksinkertaisia, kuten 12345, joita
kokeillaan ensimmäisenä. Uusissa laitteissa on alettu käyttää
satunnaisia laitekohtaisia salasanoja, joissa ei ole yhtä suurta riskiä,
mutta salasanan vaihdosta ei silloinkaan ole haittaa.

Lähes yhtä tärkeä sääntö on päivitysten hoitaminen. Nykylaitteistossa on
ohjelmistoja, jotka tulee päivittää tietoturva-aukkojen varalta. Jopa
älyjääkaapit voivat sisältää hakkeroinnin mahdollistavia aukkoja, ja
hakkerin pääsy muihin verkon palveluihin helpottuu huomattavasti, kun
yksi laite on murrettu. Kaikki älyä ja tietotekniikkaa sisältävät
laitteet tulee päivittää säännöllisesti.

Valmistajan nettisivuilta löytyy usein laitteen tuotenumeroa vastaava
firmware- eli laitteisto-ohjelmisto-tiedosto, sekä ohjeet sen
lataamiseksi laitteeseen. Yleensä tiedosto ladataan paikoilleen joko
usb-tikun tai selaimen kautta aukeavan hallintapaneelin avulla.
Päivitystiedoston ohessa on tarkat ohjeet päivityksen tekemiselle. Kuten
muissa päivityksissä, työn voi myös ostaa toimittajalta joko palveluna
tai tuntihintaan.

Herkän tietoteknisen laitteiston turvaamisessa voi lisäksi olla
tietoturvan lisäksi muita huomioitavia seikkoja. Mikäli laite tallentaa
dataa, voi se olla herkkä sähkökatkoksille. Tällaiset herkät laitteet,
kuten palvelimet, kannattaa suojata varavoimajärjestelmällä
(UPS---uninterruptible power source), joka turvaa sähkönsyötön
akkuvirralla lyhyissä sähkökatkoksissa ja varmistaa pidemmissä
katkoksissa laitteen turvallisen alasajon. Nämä laitteet yleensä
suojaavat myös salamaniskuilta, ja ukonilman varalta voi ostaa myös
pelkän suojan ilman akkua.

Mikäli laitteiden mukauttamiseen ja asetusten säätöön on laitettu paljon
aikaa, voi niiden varmuuskopiointi olla hyödyllistä. Lisäksi kannattaa
tehdä riskianalyysi laiterikkojen varalle. Kriittinen infrastruktuuri
voi olla järkevää turvata varalaitteistolla, ja suunnitelma laiterikkoon
varautumiseksi voi lyhentää toimintavalmiuden palauttamista, kun aikaa
ei mene ihmettelyyn.

> Tärkeimmät vinkit
> 
> -   Vaihda uusi salasana tehdassalasanojen tilalle kaikkiin laitteisiin
> -   Aikatauluta ja suorita tietoturvapäivitykset myös laitteistolle
> -   Tee riskianalyysi ja suunnitelma laitteistorikkojen varalta

## Massamuistit, kovalevyt ja usb-tikut

USB-muistien ja ulkoisten kovalevyjen käytössä kannattaa välttää tuntemattomia tai epäluotettavia laitteita. Käytä ainoastaan luotettavilta valmistajilta ja myyjiltä peräisin olevia massamuisteja. Älä käytä suojaamattomissa laitteissa olleita massamuisteja tai löydettyjä usb-tikkuja.

Arkaluontoinen materiaali kannattaa suojata salauksella (kryptauksella). Yksinkertaisimmillaan tämä tapahtuu klikkaamalla levyä tiedostonhallintaohjelmassa hiiren oikealla napilla ja salaamalla se avautuvasta valikosta Bitlocker- (Windows) tai Finder-ohjelmalla (Mac). Salaus estää tietoja vuotamasta, jos laite joutuu vääriin käsiin.

## Monivaiheinen tunnistautuminen

Monivaiheinen tai kaksivaiheinen (MFA tai 2FA) kysyy salasanan lisäksi
tunnistautumista jollain toisella tavalla---esimerkiksi
tekstiviestikoodilla tai mobiilisovelluksella---jolloin varmistetaan,
että sisään kirjautuva käyttäjä on oikean puhelimen tai muun
MFA-työkalun omistaja. Tämä varmistaa, että vaikka salasana vuotaisi
kolmannelle osapuolelle, he eivät voi kirjautua järjestelmään pelkällä
salasanalla.

Monivaiheinen tunnistautuminen estää suurimman osan
identiteettivarkauksista ja phishing-hyökkäyksistä. Se suojaa tilisi
erittäin luotettavasti, sillä järjestelmään tunkeutuakseen hakkerin
täytyy päihittää monta suojaustasoa. Etenkin liiketoiminta- ja
mainekriittisten järjestelmien kirjautuminen on hyvä suojata
monivaiheisella tunnistautumisella.

Hyökkäystyökalujen kehittyessä MFA-suojauksenkaan päihittäminen ei ole
täysin mahdotonta, esimerkiksi kysymällä lisäkoodia
huijaus-pankki-sivustolla, joten salasanaa käytettäessä kannattaa aina
tarkistaa selaimen osoiteriviltä, että palvelu on luotettava (lisää
kohdassa Osoiterivin ja nettilinkkien lukutaito). Sähköposti ja
tekstiviesti ovat fyysisiä salausavaimia ja MFA-tunnuslukuohjelmia
hieman heikompia, mutta mikä tahansa monivaiheinen tunnistautuminen
lisää turvallisuutta erittäin paljon.

> Tärkeimmät vinkit
> 
> -   Monivaiheinen tunnistautuminen estää suurimman osan
>     identiteettivarkauksista

## Osoiterivin ja nettilinkkien lukutaito

Hyvänä esimerkkinä ymmärryksen kasvattamasta kyberturvasta toimii
osoitekentän lukutaito. Osoitekentän vasemmalla puolella on yleensä
lukon kuva, joka tarkoittaa että yhteys avatulle sivulle on salattu, eli
tietoja ei pysty helposti lukemaan välistä esimerkiksi kahvilan huonosti
suojatun verkon kautta. Se ei kuitenkaan tarkoita, että sivun sisältö
olisi luotettava. Myös väärennetty sivu voi olla salattu. Ensimmäisenä
osoitteessa lukee protokolla, yleensä http (salaamaton) tai https
(salattu), joskin monet selaimet piilottavat tämän näkyvistä.

Varsinaisen osoitteen ensimmäinen osa on domain tai verkkotunnus, jonka
eri osat erotetaan pisteellä. Sitä luetaan käänteisesti oikealta
vasemmalle. Päätason domain voi olla maakohtainen .fi tai viestiä
sivuston tyypistä (esim. .org on usein voittoa tavoittelematon
organisaatio). Seuraavana oikealta on toisen tason domain, joka on
pitänyt ostaa ja jota hallinnoi jokin organisaatio tai yksityishenkilö.
Tämän edessä voi olla yksi tai useampi pisteellä erotettu alidomain,
jotka voidaan ohjata eri sivustoille tai palveluihin. Esimerkiksi
google.com on Googlen omistama domain, jonka alidomainit mail.google.com
ja drive.google.com ovat Googlen eri palveluja.

Domainin oikealla puolella on osoitteen polku---kansiorakenne, jota
domainin takana olevalta tietokoneelta kysytään. Kansiot ja alikansiot
erotellaan / -merkillä. Polun jälkeen voi vielä olla kysymysmerkki,
jonka jälkeen sivulle annetaan parametrejä ja/tai ristikkomerkki
("risuaita"), jonka jälkeinen teksti osoittaa sivun osioon.

Tärkeintä tietoturvan kannalta on toisen tason domain. Esimerkiksi
domain nordea.x64.secure.app.com ei liity mitenkään Nordea-pankkiin,
vaan on app.com -domainin alla, eikä siten luotettava pankkiasioinnissa,
vaikka lukon kuva osoiteriviltä löytyisikin. Secure on toisen
alidomainin nimi, eikä sekään kerro turvallisuudesta.

## Pilvipalvelut ja palvelimet

Pilvipalvelujen käyttö on tietoturvan kannalta helpompaa kuin omien
palvelimien ylläpito, mutta kyberturva tulee silti ottaa huomioon
palvelujen asetuksissa ja käyttäjätunnuksissa.

Jaettuja käyttäjätunnuksia ei kannata tehdä, vaan jokaiselle käyttäjälle
tulee luoda omat tunnukset heidän tarvitsemiinsa palveluihin. Parhaassa
tapauksessa käyttäjätunnukset hallinnoidaan keskitetysti, jolloin
käyttäjän tarvitsee kirjautua sisään vain kerran käyttääkseen kaikkia
palveluja, mutta usein pienessä yrityksessä tähän ei ole resursseja.
Silloinkin kannattaa käyttäjille luoda omat tunnukset eri palveluihin,
ja käyttää jonkinlaista salasanojen hallintaohjelmaa (katso oma luku
salasanoista).

Mikäli pilvipalveluja käytetään omien virtuaalipalvelimien
hallinnointiin, kannattaa niiden tietoturva-asetusten suunnitteluun
käyttää ammattiapua. Palveluna toimitettavan pilvisähköpostin tai muun
paketin asetukset riippuvat palveluntarjoajasta, joten riskien määrä
riippuu valitun kumppanin tietoturvatasosta.

Vaikka pilvipalvelujen toimintavarmuus on melko hyvä, kannattaa niiden
tieto silti varmuuskopioida itse. Suurenkin yhteistyökumppanin
palvelimet voivat vioittua, ja paikallinen varmuuskopio esimerkiksi
ulkoiselle kovalevylle voi pelastaa paljon, jos kaikki pilven tiedot
häviävät.

## Päivitykset

Suurin osa tietokoneista ja älypuhelimista päivittää itsensä
automaattisesti, kunhan varmistaa että päivitysten haku on päällä. Myös
pilvipalvelut päivittyvät toimittajan toimesta, ellei toisin ole
esimerkiksi käyttöehdoissa sovittu. Erityistä huomiota tulee kiinnittää
palvelimien, laitteistojen ja erityisohjelmien kanssa, sillä niiden
päivityksistä joutuu huolehtimaan erikseen.

Mikäli päivityslistan asioita ei pysty laskemaan sormilla, kannattaa
miettiä ohjelmistorekisterin perustamista. Yksinkertaisimmillaan se voi
olla lista käytössä olevista laitteista, niiden käyttäjistä ja
viimeisimmästä päivityspäivämäärästä. Aikatauluta päivitykset sopivalla
syklillä, esimerkiksi pari kertaa vuodessa. Parhaassa tapauksessa
päivitystilannetta valvotaan ja uusiin päivityksiin reagoidaan heti.

Laitteiden päivitystiedostot ladataan yleensä valmistajan nettisivuilta,
joilta löytyy myös niiden päivitysohjeet. Voit myös pyytää osaavan
IT-tekijän päivittämään laitteet joko jatkuvana palveluna tai
tuntihintaan sovituin väliajoin. Mikäli laitteelle ei enää ole
valmistajan tukea eikä sille tehdä tietoturvapäivityksiä, on vain ajan
kysymys, milloin se lakkaa olemasta turvallinen. Tällainen laite
kannattaa korvata uudemmalla tai vähintään eristää verkosta.

Työkoneilta kannattaa mahdollisuuksien mukaan poistaa tarpeettomat
ohjelmistot, etenkin jos niitä käytetään kriittisen tiedon käsittelyyn.
Mitä enemmän ohjelmia on, sitä enemmän on myös
tietomurtomahdollisuuksia. Työtä ei kuitenkaan tule hankaloittaa
liiallisella turvallisuudella.

> Tärkeimmät vinkit
> 
> -   Varmista että automaattipäivitykset ovat käytössä
> -   Aikatauluta palvelimien, laitteistojen ja ohjelmistojen päivitysten
>     seuranta ja asennus
> -   Älä käytä ohjelmia tai laitteita, joita ei tueta ja joille ei enää
>     tehdä päivityksiä

## Salasanat

Älä käytä samaa salasanaa useaan paikkaan.

Salasana on vain niin turvassa kuin heikoin paikka, jossa sitä on
käytetty. Niinpä eri sivustoille kannattaa tehdä eri salasanat, jotta
harrastefoorumilta hakkeroidulla salasanalla ei voida kirjautua
sähköpostiin tai maksupalveluihin. Laitteiden tehdasasetusten
vakiosalasanat ovat käytössä laaja-alaisesti ja yleisesti tiedossa,
joten niiden vaihtaminen on erityisen tärkeää.

Monen eri salasanan muistaminen on hankalaa, joten käytännössä eri
salasanan luominen jokaiseen palveluun vaatii salasanojen kirjoittamisen
ylös. Paperimuistion sijaan kannattaa käyttää salasanojen hallintaan
luotua salattua sovellusta. Hyviä ja helppoja työkaluja salasanojen
hallintaan ovat mm. Bitwarden, NordPass ja KeePassXC. Salasanojen
hallintatyökalu vaatii yhden salasanan muistamisen---ohjelma muistaa
loput salasanat.

Hyväkin salasana on mahdollista vuotaa, joten paras turva saadaan kun
pelkkä salasana ei riitä, vaan sisäänkirjautumiseen vaaditaan
monivaiheinen tunnistautuminen.

> Tärkeimmät vinkit
> 
> -   Salasanojen hallintatyökaluja ovat mm. Bitwarden, NordPass ja
>     KeePassXC. Luo tällaiseen palveluun yksi salalause, jonka muistat,
>     ja tallenna loput salasanat työkaluun. Huolehdi myös
>     varmuuskopioista ja ota tärkeissä palveluissa käyttöön monivaiheinen
>     tunnistautuminen.

Salasana voi nykyisin olla hyvinkin pitkä salalause, sillä salasana on
sitä turvallisempi mitä pidempi se on. Hyvä salasana on helppo muistaa,
joten erinomainen salasana voi olla jokin isoja kirjaimia ja
erikoismerkkejä sisältävä lause. Salasanoja automaattisesti arvaavat
ohjelmat käyttävät usein sanakirjaa, joten puhekielen ilmaukset,
murresanat ja kirjoitusvirheet tekevät salasanasta vahvemman.
Salasanojen hallintaan käytetyt ohjelmat voivat myös luoda täysin
satunnaisen salasanan, joka kopioidaan palvelun salasanakenttään.

Tärkeää on myös, että kaikilla työntekijöillä on henkilökohtaiset
salasanat eri palveluihin, eikä yhtä yhteistä salasanaa. Näin salasanan
vuotaessa tai henkilön vaihtuessa on helppo sulkea vain yksi tili.
Tärkeimmät tilit kannattaa suojata monivaiheisella tunnistautumisella.

Yrityksen salasanaohjeistuksen tulisi sisältää ohjeet salasanan
tekemiseen ja käyttöön. Tunnusten luovutuksen ja sulkemisen tulisi myös
olla hallittua---joko jonkin keskitetyn järjestelmän kautta tai
muistilistana, jotta esimerkiksi työntekijän poistuttua muistetaan
sulkea tai muuttaa kaikki hänellä käytössä olleet tunnukset.

> Tärkeimmät vinkit
> 
> -   Peruskäytössä ei tule käyttää järjestelmänvalvojan (admin/root)
>     oikeuksia
> -   Käytä monivaiheista tunnistautumista tärkeissä palveluissa, kuten
>     sähköpostissa
> -   Käytä salasanalistaa/ohjelmaa---älä käytä uudelleen samaa salasanaa
>     moneen palveluun
> -   Hyvä salasana voi olla pitkä erikoismerkkejä sisältävä salalause

## Selaimen valinta

Minkä tahansa yleisen ja päivityksissä ajan tasalla olevan selaimen
käyttö on itsessään turvallista. Yksityisyyden kannalta selaimissa on
kuitenkin eroja. Chrome ja Edge-selaimet tallentavat käytöstään tietoja
Googlen tai Microsoftin palvelimille käyttökokemuksen parantamiseksi, ja
käyttäjien tietoja on helppo käyttää myös mainostukseen. Mikäli omien
tietojen yksityisyydestä haluaa pitää kiinni, kannattaa käyttää jotakin
muuta selainta. Incognito-tilan käyttö ei estä tiedon keräämistä, vaan
ainoastaan pitää käyttäjän itsensä näkemän selainhistorian puhtaana.

Firefox on ilmainen avoimen lähdekoodin selain, joka on vakaa ja
luotettava. Siitä on myös Librewolf-nimellä toimiva versio, joissa
asetukset on valmiiksi säädetty suojaamaan yksityisyyttä ja estämään
mainokset. Brave on toinen, Chromeen pohjautuva selain, jossa asetuksia
on säädetty yksityisempään suuntaan. Brave jakaa kuitenkin mielipiteitä,
sillä yritys on käyttänyt selainta kryptovaluuttapalvelujen
mainostamiseen. Yksityisyyden suojausasetukset saattavat kuitenkin
aiheuttaa ongelmia joidenkin nettisivujen toiminnassa. Valitse selain
oman riskiprofiilin mukaan. Parasta voi olla asentaa tiukasti turvattu
selain päivittäiseen käyttöön ja toinen selain, jota voi käyttää jos
eteen tulee yhteensopivuusongelmia. Firefox on aina hyvä valinta, jos ei
halua kokeilla eri vaihtoehtoja.

Yksityiseen ja salattuun selailuun paras työkalu on Tor Browser, joka
salaa selailuun liittyvän tiedonsiirron kuten VPN ja pitää
selainhistorian salassa. Ohjelma on suunniteltu vastustamaan seurantaa
ja ohittamaan yhteydentarjoajien verkkosivuestot. Ohjelman voi ladata
osoitteesta www.torproject.org.

## Tiedonsiirto ja lähiverkot

Nykypäivänä isojen toimittajien verkkolaitteet, kuten internet-yhteyden
mukana tuleva reititin, ovat perusasetuksiltaan melko hyvin suojattu. On
kuitenkin hyvä varmistaa, että langaton verkko kysyy salasanaa, ja että
laitteiden pohjaan merkitty salasana on jotain muuta kuin perusmuotoinen
1234, abcd tai muuta vastaavaa. Tällainen yleisesti tiedossa oleva
perussalasana on kuin punainen matto tunkeutujalle, joka voi
automatisoidusti kokeilla kaikki tunnetut salasanat läpi sekunneissa.

Yrityksen tietoverkot on hyvä jakaa eritasoisiin verkkoalueisiin, jotta
turvattomat laitteet eivät vaaranna turvallisuutta vaativia toimintoja.
Yksinkertaisimmillaan tämä tarkoittaa sitä, että toimistolla tulisi olla
erillinen vierasverkko, josta pääsee internettiin mutta ei yrityksen
järjestelmiin. Vaikka tämä verkko ei ole teknisesti normaalia
turvattomampi, siihen voi liittää erilaiset vierailijoiden koneet,
kotitabletit, televisiot, älylaitteet ja muut järjestelmät, jotka eivät
ole yhtä turvallisia kuin yrityksen muu laitteisto. Nykypäivänä on
tavallista, että yrityksen palomuuri onnistutaan ohittamaan jonkin
huonosti päivittyvän älylaitteen, kuten jääkaapin, avulla. Helposti
murretun laitteen jälkeen tunkeutuja pääsee yhdistämään suoraan
lähiverkon muihin laitteisiin ilman palomuurin suojaa---siksi heikot
laitteet on syytä rajata omaan verkkoonsa. Monissa reitittimissä on
erillinen vierasverkko-asetus, jonka osaava henkilö laittaa päälle
helposti.

Pääsyä eri verkkopalveluihin kannattaa rajoittaa mahdollisuuksien
mukaan. Mikäli palvelua ei ole missään tilanteessa tarpeen käyttää
ulkomailta, voidaan sen toiminta rajoittaa kotimaahan
palomuuriasetuksilla. Yrityksen kriittiset järjestelmät voidaan rajata
toimimaan vain toimiston verkosta.

VPN suojaa tiedonsiirron päätelaitteen ja palvelimen välillä, suojaten
epäluotettavien yhteyksien salakuuntelulta ja mahdollistaen turvalliset
yhteydet yritysverkon palveluihin. Lisätietoja erillisessä
VPN-aliluvussa.

## Varmuuskopiot

Varmuuskopiointi opitaan yleensä kantapään kautta sen jälkeen, kun
tietoa on ensimmäisen kerran hävinnyt. Varmuuskopioiden palautus opitaan
yleensä kantapään kautta sen jälkeen, kun tietoa on toisen kerran
hävinnyt. Tästä on kehittynyt sanonta: varmuuskopiot ovat olemassa vasta
kun niiden palautus on testattu käytännössä.

Tietojen palauttamisen voi testata vaikka uutta tietokonetta käyttöön
otettaessa leikkimällä, että vanha kone on hävinnyt---tai
kuivaharjoituksella, jossa jokin viime viikon tiedosto haetaan
varmuuskopioista ja todetaan toimivaksi. Myös tietojen
ylikirjoittamisesta palautuminen kannattaa varmistaa---saako
varmuuskopiosta oikeat tiedot palautettua, jos tärkeän tiedoston päälle
kopioi samalla nimellä väärän tiedoston? Tällöin voidaan palautua myös
kiristyshaittaohjelmien vaikutuksista.

> Tärkeimmät vinkit
> 
> -   Varmuuskopiot ovat olemassa vasta kun niiden palautus on testattu
>     käytännössä!

Kuinka nopeasti uudella koneella pääsee tekemään normaalisti töitä, jos
tietoja ei saa kopioida vanhalta koneelta vaan ne pitää palauttaa
varmuuskopioista? Parhaassa tapauksessa kaikki tarpeellinen tieto
saadaan täysin käyttöön ilman että tähän kuluu paljoakaan työaikaa.
Työhön liittyvän tiedon säilyttäminen esimerkiksi Dropbox, Onedrive tai
Tresorit -tyyppisen pilvipalveluun peilattavan kansion alla tekee
palautumisesta erittäin helppoa: asenna pilvipalvelun ohjelma ja
kirjaudu sisään. Tiedot ovat tallessa sekä omalla tietokoneella että
pilvessä.

Varmista kuitenkin ennen pilvipalvelun käyttöönottoa, että sinne
tallennettava data saa siirtyä pilveen. Esimerkiksi GDPR-säädöksen
puitteissa yritysten tallentaman henkilötiedon pitää ensisijaisesti
pysyä EU-alueella, ja joillain palveluntarjoajilla tulee erikseen valita
palvelimen sijainti USA:n ja EU:n välillä.

Pilvipalvelu ei kuitenkaan ole varmuuskopio, mikäli tietoa säilytetään
vain pilvessä. Myös pilvipalveluntarjoajan laitteisto voi rikkoutua, ja
tietoa hävitä. Tästä syystä on tärkeää että, tieto on tallessa vähintään
kahdessa paikassa.

Liiketoimintakriittisen tiedon tallennukseen kannattaa käyttää
3-2-1-sääntöä: Tee tiedosta kolme kopiota, kahdelle erityyppiselle
medialle (DVD, kovalevy, pilvi), joista yksi on fyysisesti eri paikassa
kuin muut.

## VPN

VPN (Virtual Private Network) salaa internet-yhteyden tietokoneelta
VPN-tarjoajan palvelimelle, mistä yhteys jatkaa eteenpäin normaalisti.
VPN-palvelimen voi myös asentaa oman toimiston verkkoon, jolloin
esimerkiksi kotoa voi yhdistää VPN-yhteydellä toimiston verkkoon.

VPN-yhteyden käytöllä on kaksi vaikutusta tietoturvaan: 1) Tieto on
salattu VPN-tarjoajalle asti, eli internet-yhteyden tai langattoman
verkon tarjoaja ei pysty salakuuntelemaan mitä tietoa linjalla kulkee;
2) Ulospäin näkyvä yhteysosoite, eli koneen IP-osoite, näyttää
käytetyille palveluille tulevan VPN-tarjoajan tietokoneelta. Vierailtu
sivusto ei siis näe käyttäjän oikeaa IP-osoitetta tai geografista
lokaatiota, vaan VPN-yhteyden osoitteen ja lokaation.

VPN-yhteys suojaa tiedonsiirtoa etenkin epäluotettavilta
yhteydentarjoajilta, mikä saattaa olla isompi huolenaihe ulkomaisessa
hotellissa kuin kotona suomalaisen yhteydentarjoajan liittymiä
käytettäessä. Se myös mahdollistaa sellaisten palvelujen käytön, joiden
toiminta on rajattu johonkin tiettyyn maahan, mikäli VPN-yhteys
muodostetaan sopivan maan kautta.

VPN-palvelimen käyttö toimistolla mahdollistaa sisäisten palvelujen,
kuten yrityksen tiedostopalvelimen, käytön estämisen julkisesta
verkosta. Tällöin palvelu toimii vain fyysisesti toimistolla ja
yrityksen VPN-yhteydellä. Tämä mahdollistaa rajattujen palvelujen
paremman suojauksen, kun niiden käyttö vaatii VPN-tunnuksen tietämisen.

VPN-yhteys voi jonkin verran lisätä viivettä ja hidastaa
latausnopeuksia, sillä yhteys kiertää VPN-tarjoajan laitteiston läpi ja
voi ruuhkautua. Lisäksi kaikki se salaamaton tieto, joka olisi kulkenut
internet-yhteydentarjoajan läpi, kulkee nyt VPN-tarjoajan palvelinten
läpi, ja epäluotettava VPN-tarjoaja voi jopa itse kuunnella yhteyksiä ja
myydä tietoja eteenpäin. VPN-tarjoajan valinta kannattaa tehdä
luotettavuutta silmällä pitäen.
