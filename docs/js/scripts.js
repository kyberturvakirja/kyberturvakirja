/*!
* Start Bootstrap - New Age v6.0.7 (https://startbootstrap.com/theme/new-age)
* Copyright 2013-2023 Start Bootstrap
* Licensed under MIT (https://github.com/StartBootstrap/startbootstrap-new-age/blob/master/LICENSE)
*/
//
// Scripts
// 

window.addEventListener('DOMContentLoaded', event => {

    // Activate Bootstrap scrollspy on the main nav element
    const mainNav = document.body.querySelector('#mainNav');
    if (mainNav) {
        new bootstrap.ScrollSpy(document.body, {
            target: '#mainNav',
            offset: 74,
        });
    };

    // Collapse responsive navbar when toggler is visible
    const navbarToggler = document.body.querySelector('.navbar-toggler');
    const responsiveNavItems = [].slice.call(
        document.querySelectorAll('#navbarResponsive .nav-link')
    );
    responsiveNavItems.map(function (responsiveNavItem) {
        responsiveNavItem.addEventListener('click', () => {
            if (window.getComputedStyle(navbarToggler).display !== 'none') {
                navbarToggler.click();
            }
        });
    });

    let repoName = "kyberturvakirja/kyberturvakirja"; // Repository name
    let url = `https://api.github.com/repos/${repoName}/releases`;
    let request = new XMLHttpRequest();
    request.open('GET', url, true);
    request.onload = function () {
        let releases = JSON.parse(this.response);
        let sum = 0;
        // Count downloads for each asset of every release
        if (Array.isArray(releases)) {
            for (const release of releases) {
                for(const asset of release['assets']) {
                    sum += asset['download_count'];
                }
            }
        } else if (releases['assets'] !== undefined) {
            for(const asset of releases['assets']) {
                sum += asset['download_count'];
            }
        }
        let output = "Ladattu " + sum.toLocaleString('fi') + " kertaa"
        document.getElementById('download').innerHTML = output;
    };
    request.send();

});
