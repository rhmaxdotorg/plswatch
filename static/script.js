//
// script.js
//

var stream = new EventSource("/stream");
var output = document.getElementById("output");
var counter = document.getElementById("counter");
var tokenCounts = {};
var currentIndices = {};
var currentHighlight = null;
var autoScroll = true;

// unlimited lines causes client browser to freeze up
// make sure to sync this with plsnow.py MAX_TOKEN value
const MAX_LINES = 1000;

document.addEventListener('click', function() {
    if(currentHighlight) {
        currentHighlight.classList.remove('highlight');
        currentHighlight = null;
    }
});

document.body.addEventListener('keydown', function(e) {
    if(e.keyCode === 32 || e.key === ' ') {
        autoScroll = !autoScroll;
        e.preventDefault();
    }
});

window.addEventListener('resize', adjustCounterHeight);

function adjustCounterHeight() {
    var counter = document.getElementById('counter');
    var rect = counter.getBoundingClientRect();
    var maxHeight = window.innerHeight - rect.top - 10;

    counter.style.maxHeight = maxHeight + 'px';
}

adjustCounterHeight();

let updateTimeout = null;

function requestUpdateCounter() {
    if (!updateTimeout) {
        updateTimeout = setTimeout(() => {
            updateCounter();
            updateTimeout = null;
        }, 100); // update every 100ms for better performance
     }
}

function updateCounter() {
    counter.innerHTML = '';

    var entries = Object.entries(tokenCounts).filter(([token, count]) => count > 0);

    entries.sort(function(a, b) {
        return b[1] - a[1];
    });

    for (var i = 0; i < entries.length; i++) {
        (function(i) {
            var token = entries[i][0];
            var count = entries[i][1];

            var truncatedToken = token.length > 16 ? token.substring(0, 12) + '...' : token;

            var container = document.createElement('div');
            container.className = 'container';

            var link = document.createElement('a');

            link.className = 'token';
            link.textContent = truncatedToken;
            link.href = 'javascript:void(0);';
            link.onclick = function(event) {
                event.stopPropagation();
                findToken(token);
            };

            var countSpan = document.createElement('span');
            countSpan.className = 'count';
            countSpan.textContent = count;

            container.appendChild(link);
            container.appendChild(countSpan);
            counter.appendChild(container);
        })(i);
    }
}

function findToken(token) {
    var regex = new RegExp(token, 'i');
    var elements = document.getElementById('output').getElementsByTagName('div');
    var startIndex = currentIndices[token] || 0;

    if(currentHighlight) {
        currentHighlight.classList.remove('highlight');
    }

    for (var i = startIndex; i < elements.length; i++) {
        if (regex.test(elements[i].textContent)) {
            elements[i].scrollIntoView();
            // scrollToElement(elements[i]);
            currentIndices[token] = i + 1;

            elements[i].classList.add('highlight');
            currentHighlight = elements[i];

            return;
        }
    }

    currentIndices[token] = 0;
}

// function scrollToElement(element) {
//     const offset = 50;
//     const elementPosition = element.getBoundingClientRect().top + window.pageYOffset();
//     const offsetPosition = elementPosition - offset;

//     window.scrollTo({
//         top: offsetPosition,
//         behavior: 'smooth'
//     });
// }

function syncTokenCounts() {
    fetch('/tokens')
        .then(response => response.json())
        .then(data => {
            tokenCounts = data;
            updateCounter();
        });
}

stream.onmessage = function(event) {
    var newLine = document.createElement("div");

    newLine.innerHTML = event.data;

    output.appendChild(newLine);

    if(autoScroll) {
        output.scrollTop = output.scrollHeight;
    }

    syncTokenCounts();

    while(output.children.length > MAX_LINES) {
        output.removeChild(output.firstChild);
    }
};
