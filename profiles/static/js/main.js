// Get the dropdown buttons and content
var dropdowns = document.querySelectorAll('.dropdown');
var dropdownContents = document.querySelectorAll('.dropdown-content');

// Toggle the dropdown content when the button is clicked
dropdowns.forEach(function(dropdown, index) {
  dropdown.addEventListener('click', function() {
    dropdownContents[index].classList.toggle('show');
  });
});

// Close the dropdown content when the user clicks outside of it
window.addEventListener('click', function(event) {
  dropdownContents.forEach(function(dropdownContent) {
    if (!event.target.matches('.dropdown') && dropdownContent.classList.contains('show')) {
      dropdownContent.classList.remove('show');
    }
  });
});

// Get the mega dropdown buttons and content
var megaDropdowns = document.querySelectorAll('.mega-dropdown');
var megaDropdownContents = document.querySelectorAll('.mega-dropdown-content');

// Toggle the mega dropdown content when the button is clicked
megaDropdowns.forEach(function(megaDropdown, index) {
  megaDropdown.addEventListener('mouseover', function() {
    megaDropdownContents[index].classList.add('show');
  });
  megaDropdown.addEventListener('mouseout', function() {
    megaDropdownContents[index].classList.remove('show');
  });
});

// Close the mega dropdown content when the user clicks outside of it
window.addEventListener('click', function(event) {
  megaDropdownContents.forEach(function(megaDropdownContent) {
    if (!event.target.matches('.mega-dropdown') && megaDropdownContent.classList.contains('show')) {
      megaDropdownContent.classList.remove('show');
    }
  });
});
