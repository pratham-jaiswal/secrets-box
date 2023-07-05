function handleClick(event) {
    let clickedElement = event.target;
    let commentBtnId = clickedElement.id;
    let commentsId = commentBtnId.replace("-opencomments", "-comments")
    let commentsSection = document.getElementById(commentsId);
    commentsSection.classList.toggle('hidden');
    console.log("Clicked element ID: " + commentsSection);

    let allCommentsSections = document.getElementsByClassName('comments');

    for (let i = 0; i < allCommentsSections.length; i++) {
        let currentCommentsSection = allCommentsSections[i];
        if (currentCommentsSection.id === commentsId) {
            continue;
        }
        currentCommentsSection.classList.add('hidden');
    }
}

window.addEventListener('DOMContentLoaded', function() {
    let elements = document.getElementsByClassName('fa-regular fa-comment');
    for (let i = 0; i < elements.length; i++) {
        elements[i].addEventListener('click', handleClick);
    }
});